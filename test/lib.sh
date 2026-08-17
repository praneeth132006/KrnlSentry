#!/usr/bin/env bash
# shellcheck shell=bash
#
# ┌───────────────────────────────────────────────────────────────────────────┐
# │  FOR LOCAL VM / CONTAINER TESTING ONLY.                                   │
# │                                                                           │
# │  Every script in this directory exists to make KrnlSentry produce an       │
# │  alert so you can confirm a detection works. They are demonstration        │
# │  harnesses, not attack tools:                                              │
# │                                                                           │
# │    • Nothing here connects to a non-loopback address.                     │
# │    • Nothing here exploits anything — the privilege-escalation scripts    │
# │      make syscalls that are *expected to fail* with EPERM. KrnlSentry      │
# │      traces syscall entry, so a denied attempt alerts exactly like a       │
# │      successful one, which is what makes safe testing possible.            │
# │    • Nothing here persists, escalates, or touches anything outside /tmp.  │
# │                                                                           │
# │  Run them in a throwaway VM or container. Do not run them on a shared     │
# │  or production host — not because they are dangerous, but because they    │
# │  create noise in somebody else's security monitoring, and a colleague     │
# │  investigating a fake reverse shell at 2am will not find it funny.         │
# └───────────────────────────────────────────────────────────────────────────┘
#
# Shared helpers, sourced by each scenario script.

set -euo pipefail

# Unprivileged identity used by scenarios that must run as a non-root user.
# Created on demand; harmless to leave behind in a throwaway environment.
DEMO_UID="${DEMO_UID:-4242}"
DEMO_GID="${DEMO_GID:-4242}"
DEMO_USER="${DEMO_USER:-ksdemo}"

# Loopback port for the reverse-shell demo. Loopback only, always.
DEMO_PORT="${DEMO_PORT:-14444}"

ks::heading() {
	printf '\n\033[1;36m── %s\033[0m\n' "$*"
}

ks::step() {
	printf '  \033[2m→\033[0m %s\n' "$*"
}

ks::warn() {
	printf '  \033[1;33m!\033[0m %s\n' "$*" >&2
}

ks::fail() {
	printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2
	exit 1
}

# ks::require_root — most scenarios need root to create a demo user or a setuid
# file. The *interesting* syscalls are then made as an unprivileged user; root
# here is scaffolding, not part of what is being demonstrated.
ks::require_root() {
	if [[ "$(id -u)" -ne 0 ]]; then
		ks::fail "must run as root (it creates a demo user and drops privileges deliberately)"
	fi
}

# ks::require_cmd — fail early and clearly rather than midway through a scenario.
ks::require_cmd() {
	local cmd
	for cmd in "$@"; do
		command -v "$cmd" >/dev/null 2>&1 || ks::fail "missing required command: $cmd"
	done
}

# ks::ensure_demo_user — create the unprivileged account used by the
# privilege-escalation scenarios.
#
# A dedicated throwaway uid rather than "nobody": nobody is used by real system
# services, and attributing demo alerts to it would muddy exactly the kind of
# investigation this tool is meant to support.
ks::ensure_demo_user() {
	ks::require_root

	if id -u "$DEMO_USER" >/dev/null 2>&1; then
		return
	fi

	ks::step "creating unprivileged demo user ${DEMO_USER} (uid ${DEMO_UID})"

	groupadd -g "$DEMO_GID" "$DEMO_USER" 2>/dev/null || true
	useradd -u "$DEMO_UID" -g "$DEMO_GID" -M -s /bin/sh "$DEMO_USER" 2>/dev/null || true
}

# ks::banner — printed by every scenario so a stray copy of one of these scripts
# is self-identifying.
ks::banner() {
	printf '\033[1m%s\033[0m\n' "$1"
	printf '\033[2mLOCAL VM/CONTAINER TESTING ONLY — generates security alerts by design\033[0m\n'
}
