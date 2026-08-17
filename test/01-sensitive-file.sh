#!/usr/bin/env bash
#
# Scenario 1 — Sensitive File Access  (rule: sensitive-file-access, T1003/T1552)
#
# FOR LOCAL VM / CONTAINER TESTING ONLY. See lib.sh for the full warning.
#
# WHAT THIS DOES
#   Opens a series of credential-bearing files read-only and immediately closes
#   them. Nothing is copied, transmitted, modified or even fully read — the
#   openat() syscall alone is what KrnlSentry matches on, so `head -c 1` is
#   sufficient to demonstrate the detection.
#
# WHY THIS IS SAFE
#   Reading /etc/shadow as root is something the system does routinely; the
#   point is not that it is dangerous but that it is *worth noticing*. No file
#   is written and no content leaves the machine.
#
# EXPECTED ALERTS
#   /etc/shadow          → HIGH    T1003.008
#   /etc/sudoers         → MEDIUM  T1552
#   /etc/sudoers.d/*     → MEDIUM  T1552
#   ~/.ssh/id_rsa        → MEDIUM  T1552.004
#   ~/.aws/credentials   → MEDIUM  T1552.001
#   /proc/<pid>/maps     → MEDIUM  T1003.007

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ks::banner "Scenario 1 — Sensitive File Access"

# Files that exist on essentially every Linux host.
ks::heading "Reading credential stores"

read_quietly() {
	local path="$1"
	if [[ -e "$path" ]]; then
		ks::step "open $path"
		head -c 1 "$path" >/dev/null 2>&1 || ks::warn "permission denied (the openat still alerts)"
	else
		ks::warn "$path not present on this host; skipping"
	fi
}

read_quietly /etc/shadow
read_quietly /etc/sudoers

# sudoers.d fragment. Created only if the directory exists and is empty, so the
# glob rule has something to match; removed again immediately.
if [[ -d /etc/sudoers.d ]]; then
	fragment=/etc/sudoers.d/krnlsentry-demo
	# Deliberately NOT valid sudo policy — a comment only. Even in the window
	# where it exists it grants nothing.
	if printf '# KrnlSentry demo fragment — grants nothing\n' >"$fragment" 2>/dev/null; then
		ks::step "open $fragment"
		head -c 1 "$fragment" >/dev/null 2>&1 || true
		rm -f "$fragment"
	fi
fi

ks::heading "Reading private key and cloud credential paths"

# These usually do not exist. Create decoys containing obvious placeholder text
# so the path-matching rules have something to open, then delete them.
# The content is never a real key.
demo_home="${HOME:-/root}"

mkdir -p "$demo_home/.ssh" "$demo_home/.aws"

decoy_key="$demo_home/.ssh/id_rsa"
decoy_aws="$demo_home/.aws/credentials"

created_key=false
created_aws=false

if [[ ! -e "$decoy_key" ]]; then
	printf 'NOT-A-REAL-KEY placeholder for KrnlSentry detection testing\n' >"$decoy_key"
	chmod 600 "$decoy_key"
	created_key=true
fi

if [[ ! -e "$decoy_aws" ]]; then
	printf '[default]\n# placeholder for KrnlSentry detection testing\n' >"$decoy_aws"
	chmod 600 "$decoy_aws"
	created_aws=true
fi

read_quietly "$decoy_key"
read_quietly "$decoy_aws"

# Clean up only what we created — never delete a real key the user already had.
$created_key && rm -f "$decoy_key"
$created_aws && rm -f "$decoy_aws"

ks::heading "Reading another process's memory map"

# A sacrificial process to inspect. Reading another process's maps is the
# reconnaissance step before memory scraping, which is why it is worth alerting
# on even though the read itself is harmless.
sleep 30 &
victim=$!
trap 'kill "$victim" 2>/dev/null || true' EXIT

sleep 0.2
ks::step "open /proc/$victim/maps"
head -c 1 "/proc/$victim/maps" >/dev/null 2>&1 || ks::warn "could not read maps"

kill "$victim" 2>/dev/null || true
wait "$victim" 2>/dev/null || true
trap - EXIT

ks::heading "Done — expect 5-6 sensitive-file-access alerts"
