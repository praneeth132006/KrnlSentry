#!/usr/bin/env bash
#
# Runs every detection scenario against a live KrnlSentry agent and reports
# which rules fired.
#
# FOR LOCAL VM / CONTAINER TESTING ONLY. See lib.sh for the full warning.
#
#   sudo ./test/run-all.sh
#   sudo ./test/run-all.sh --binary ./bin/krnlsentry
#
# This is the end-to-end check: it starts the agent, runs all four scenarios,
# stops the agent, and asserts that each rule produced at least one alert. It
# exits non-zero if any rule failed to fire, which makes it usable as a smoke
# test rather than only as a demo.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="$REPO_ROOT/bin/krnlsentry"
ALERTS="/tmp/krnlsentry-e2e-alerts.jsonl"
AGENT_LOG="/tmp/krnlsentry-e2e-agent.log"
SETTLE="${SETTLE:-2}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--binary)
		BINARY="$2"
		shift 2
		;;
	--alerts)
		ALERTS="$2"
		shift 2
		;;
	*)
		ks::fail "unknown argument: $1"
		;;
	esac
done

ks::banner "KrnlSentry end-to-end detection test"
ks::require_root

[[ -x "$BINARY" ]] || ks::fail "agent binary not found at $BINARY (run: make build)"

# Tracepoint attachment needs tracefs. In a container it is usually not mounted;
# mounting it is harmless and is what `make docker-run` does too.
if [[ ! -d /sys/kernel/tracing/events ]] && [[ ! -d /sys/kernel/debug/tracing/events ]]; then
	ks::step "mounting tracefs"
	mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null ||
		mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null ||
		ks::fail "could not mount tracefs; run the container with --privileged"
fi

rm -f "$ALERTS" "$AGENT_LOG"

ks::heading "Starting agent"

# Loopback alerts must stay enabled: scenario 4 connects to 127.0.0.1 and would
# otherwise be suppressed by design.
"$BINARY" --output "$ALERTS" >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

cleanup() {
	if kill -0 "$AGENT_PID" 2>/dev/null; then
		kill -INT "$AGENT_PID" 2>/dev/null || true
		wait "$AGENT_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT

sleep "$SETTLE"

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
	ks::fail "agent exited during startup:
$(cat "$AGENT_LOG")"
fi

ks::step "agent running (pid $AGENT_PID), alerts → $ALERTS"

# ── Scenarios ────────────────────────────────────────────────────────────────
for scenario in \
	"$SCRIPT_DIR/01-sensitive-file.sh" \
	"$SCRIPT_DIR/02-privilege-escalation.sh" \
	"$SCRIPT_DIR/03-ptrace-injection.sh" \
	"$SCRIPT_DIR/04-reverse-shell.sh"; do

	if [[ ! -x "$scenario" ]]; then
		chmod +x "$scenario" 2>/dev/null || true
	fi

	# A scenario that fails should not abort the remaining ones — the point
	# is to learn which detections work, not to stop at the first gap.
	if ! bash "$scenario"; then
		ks::warn "scenario failed: $(basename "$scenario")"
	fi

	sleep 1
done

# ── Stop the agent and let it flush ─────────────────────────────────────────
ks::heading "Stopping agent"
sleep 1
kill -INT "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
trap - EXIT

# ── Results ─────────────────────────────────────────────────────────────────
ks::heading "Results"

if [[ ! -s "$ALERTS" ]]; then
	ks::fail "no alerts were written to $ALERTS
agent log:
$(cat "$AGENT_LOG")"
fi

total=$(wc -l <"$ALERTS" | tr -d ' ')
printf '  %s alerts written to %s\n\n' "$total" "$ALERTS"

# Count per rule without requiring jq: match the rule field textually. The field
# name is a stable part of the output contract, so this is safe.
failures=0
for rule in privilege-escalation sensitive-file-access process-injection reverse-shell; do
	count=$(grep -c "\"rule\":\"$rule\"" "$ALERTS" || true)

	if [[ "$count" -gt 0 ]]; then
		printf '  \033[1;32m✓\033[0m %-24s %s alert(s)\n' "$rule" "$count"
	else
		printf '  \033[1;31m✗\033[0m %-24s no alerts\n' "$rule"
		failures=$((failures + 1))
	fi
done

printf '\n'

if command -v jq >/dev/null 2>&1; then
	ks::heading "Alerts by severity"
	jq -r '.severity' "$ALERTS" | sort | uniq -c | sed 's/^/  /'
fi

if [[ "$failures" -gt 0 ]]; then
	ks::fail "$failures rule(s) produced no alerts"
fi

ks::heading "All four detection rules fired"
