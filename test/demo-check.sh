#!/usr/bin/env bash
#
# Pre-demo check: exercises the agent the way a demo does, and asserts the
# result instead of eyeballing it.
#
#   ./test/demo-check.sh          # or: make demo-check
#
# This is deliberately not the same thing as the unit tests. detect/ already
# pins exactly which alerts the bundled capture must produce — but it does so by
# calling the engine directly, which skips the CLI, the flag parsing, the JSONL
# sink and the dashboard renderer. Every one of those is in the demo path, and
# all of them are things a demo can die on.
#
# No root, no eBPF, no Linux: it runs the replay path, so it works on the laptop
# the demo is given from.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CAPTURE="$REPO_ROOT/testdata/captures/intrusion.jsonl"
WORK="$(mktemp -d)"
BINARY="$WORK/krnlsentry"

trap 'rm -rf "$WORK"' EXIT

failures=0

ks::check() {
	local what="$1"
	shift

	if "$@" >/dev/null 2>&1; then
		printf '  \033[1;32m✓\033[0m %s\n' "$what"
	else
		printf '  \033[1;31m✗\033[0m %s\n' "$what"
		failures=$((failures + 1))
	fi
}

# ks::check_contains — assert a needle appears in a file, naming the needle in
# the output so a failure says what is missing rather than only that something is.
ks::check_contains() {
	local what="$1" file="$2" needle="$3"

	if grep -qF -- "$needle" "$file"; then
		printf '  \033[1;32m✓\033[0m %s\n' "$what"
	else
		printf '  \033[1;31m✗\033[0m %s — missing %q\n' "$what" "$needle"
		failures=$((failures + 1))
	fi
}

ks::check_count() {
	local rule="$1" file="$2" want="$3"
	local got
	# An attack-chain alert embeds its evidence in "story", and each step
	# carries a "rule" of its own — so the story is cut off the line before
	# counting, or every chain inflates the counts of the rules it cites.
	got=$(sed 's/"story":.*//' "$file" | grep -c "\"rule\":\"$rule\"" || true)

	if [[ "$got" -ge "$want" ]]; then
		printf '  \033[1;32m✓\033[0m %-24s %s alert(s)\n' "$rule" "$got"
	else
		printf '  \033[1;31m✗\033[0m %-24s %s alert(s), want at least %s\n' "$rule" "$got" "$want"
		failures=$((failures + 1))
	fi
}

ks::banner "KrnlSentry demo check"

[[ -f "$CAPTURE" ]] || ks::fail "bundled capture missing: $CAPTURE (run: make capture-fixture)"

# ── Build ───────────────────────────────────────────────────────────────────
# Plain `go build`, not `make build`: the replay path needs no eBPF object, and
# requiring clang here would make the check unrunnable on the machine the demo
# is most likely to be given from.
ks::heading "Building the agent"
ks::step "go build ./cmd/krnlsentry"
(cd "$REPO_ROOT" && go build -o "$BINARY" ./cmd/krnlsentry) || ks::fail "build failed"

# ── CLI surface ─────────────────────────────────────────────────────────────
ks::heading "CLI"
ks::check "--version prints a version" "$BINARY" --version
ks::check "--list-rules exits cleanly" "$BINARY" --list-rules

"$BINARY" --list-rules >"$WORK/rules.txt" 2>&1 || true
for rule in privilege-escalation sensitive-file-access process-injection reverse-shell attack-chain; do
	ks::check_contains "--list-rules names $rule" "$WORK/rules.txt" "$rule"
done

# A bad flag value must fail fast and say so, before anything is loaded.
if "$BINARY" --min-severity NONSENSE --replay "$CAPTURE" >/dev/null 2>&1; then
	printf '  \033[1;31m✗\033[0m invalid --min-severity is rejected\n'
	failures=$((failures + 1))
else
	printf '  \033[1;32m✓\033[0m invalid --min-severity is rejected\n'
fi

# ── Replay: the scrolling stream ────────────────────────────────────────────
ks::heading "Replay (console stream)"

ALERTS="$WORK/alerts.jsonl"
"$BINARY" --replay "$CAPTURE" --output "$ALERTS" >"$WORK/console.txt" 2>"$WORK/console.err" ||
	ks::fail "replay failed:
$(cat "$WORK/console.err")"

ks::check_count privilege-escalation "$ALERTS" 1
ks::check_count sensitive-file-access "$ALERTS" 2
ks::check_count process-injection "$ALERTS" 1
ks::check_count reverse-shell "$ALERTS" 1
ks::check_count attack-chain "$ALERTS" 1

# The fd confirmation is what separates the reverse-shell detection from a
# coincidence, so losing it would hollow out the headline finding while every
# count above still passed.
ks::check_contains "reverse shell confirms the socket fd" "$ALERTS" '"chain_socket_fd_confirmed":"true"'
ks::check_contains "attack chain carries its story" "$ALERTS" '"story":['
ks::check_contains "alerts carry a storyline id" "$ALERTS" '"storyline":"'
ks::check_contains "console shows the chain timeline" "$WORK/console.txt" "Credential Access"
ks::check_contains "summary reports the chains" "$WORK/console.err" "attack chains"

# Alert log permissions are part of the contract: alerts name paths and
# processes, and a world-readable security log is its own finding.
mode=$(stat -f '%Lp' "$ALERTS" 2>/dev/null || stat -c '%a' "$ALERTS")
if [[ "$mode" == "600" ]]; then
	printf '  \033[1;32m✓\033[0m alert log is mode 0600\n'
else
	printf '  \033[1;31m✗\033[0m alert log is mode %s, want 600\n' "$mode"
	failures=$((failures + 1))
fi

# ── Replay: the dashboard ───────────────────────────────────────────────────
ks::heading "Replay (dashboard)"

# --color forces the dashboard when stdout is not a terminal, which is exactly
# the case here. Without it the agent correctly refuses and falls back.
# Fixed geometry, because the frame adapts to the terminal: with stdout on a
# pipe there is no window size to read, and the panels a 30-row fallback sheds
# are not the ones this check is about. COLUMNS/LINES are the documented
# override for exactly this case.
COLUMNS=110 LINES=44 "$BINARY" --replay "$CAPTURE" --output "$WORK/dash.jsonl" --dashboard --color \
	>"$WORK/dash.txt" 2>"$WORK/dash.err" ||
	ks::fail "dashboard replay failed:
$(cat "$WORK/dash.err")"

# The frames carry ANSI styling, and a styled cell puts escape bytes between a
# label and its value ("drops" / "0"), so content is asserted against a
# stripped copy and the escapes themselves are asserted separately.
sed -E $'s/\x1b\\[[0-9;?]*[a-zA-Z]//g' "$WORK/dash.txt" >"$WORK/dash.plain"

for panel in "SEVERITY" "RULES" "ATT&CK TACTICS" "TOP PROCESSES" "ATTACK CHAIN" "RECENT ALERTS"; do
	ks::check_contains "dashboard draws the $panel panel" "$WORK/dash.plain" "$panel"
done

ks::check_contains "dashboard reaches 100%" "$WORK/dash.plain" "100%"
ks::check_contains "dashboard reports no drops" "$WORK/dash.plain" "drops 0"
ks::check_contains "dashboard shows the chain's first step" "$WORK/dash.plain" "cat[4120]"
ks::check_contains "dashboard shows the reverse shell" "$WORK/dash.plain" "python3[4150]"
ks::check_contains "dashboard restores the cursor on exit" "$WORK/dash.txt" $'\033[?25h'

# A frame taller than the terminal scrolls, which moves the position the next
# repaint draws from and tears the display apart — so a short terminal must get
# a shorter frame, not a clipped one.
COLUMNS=110 LINES=26 "$BINARY" --replay "$CAPTURE" --output "$WORK/short.jsonl" --dashboard --color \
	>"$WORK/short.txt" 2>/dev/null || true
sed -E $'s/\x1b\\[[0-9;?]*[a-zA-Z]//g' "$WORK/short.txt" >"$WORK/short.plain"

# Each frame runs from its header rule to its footer rule, and the painted
# frames are written one after another, so the last frame's height is the
# distance between the last of each.
first_line=$(grep -n '╭─ KrnlSentry' "$WORK/short.plain" | tail -1 | cut -d: -f1)
last_line=$(grep -n '╰─ alerts →' "$WORK/short.plain" | tail -1 | cut -d: -f1)
short_lines=$((last_line - first_line + 1))

if [[ "$short_lines" -le 26 ]]; then
	printf '  \033[1;32m✓\033[0m 26-row terminal gets a %s-line frame\n' "$short_lines"
else
	printf '  \033[1;31m✗\033[0m 26-row terminal got a %s-line frame\n' "$short_lines"
	failures=$((failures + 1))
fi

ks::check_contains "short frame keeps the alert totals" "$WORK/short.plain" "RECENT ALERTS"

# Without a terminal and without --color, the dashboard must decline rather than
# write escape codes into what is probably a log file.
"$BINARY" --replay "$CAPTURE" --output "$WORK/fallback.jsonl" --dashboard \
	>"$WORK/fallback.txt" 2>"$WORK/fallback.err" || true
ks::check_contains "dashboard declines a non-terminal" "$WORK/fallback.err" "needs a terminal"

if grep -q $'\033\[H' "$WORK/fallback.txt"; then
	printf '  \033[1;31m✗\033[0m fallback wrote cursor control into a pipe\n'
	failures=$((failures + 1))
else
	printf '  \033[1;32m✓\033[0m fallback writes no cursor control into a pipe\n'
fi

# ── Pacing ──────────────────────────────────────────────────────────────────
ks::heading "Paced replay"

# The bundled capture spans ~34s. At 100× it must finish in a couple of
# seconds; if pacing ignored --replay-speed it would take the full 34.
start=$(date +%s)
"$BINARY" --replay "$CAPTURE" --output "$WORK/paced.jsonl" --replay-speed 100 >/dev/null 2>&1
elapsed=$(($(date +%s) - start))

if [[ "$elapsed" -lt 10 ]]; then
	printf '  \033[1;32m✓\033[0m --replay-speed 100 finished in %ss\n' "$elapsed"
else
	printf '  \033[1;31m✗\033[0m --replay-speed 100 took %ss\n' "$elapsed"
	failures=$((failures + 1))
fi

# Same alerts, whatever the pacing: the clock must not change the verdict.
if diff -q <(cut -d, -f2- "$ALERTS") <(cut -d, -f2- "$WORK/paced.jsonl") >/dev/null; then
	printf '  \033[1;32m✓\033[0m pacing does not change the alerts\n'
else
	printf '  \033[1;31m✗\033[0m paced replay produced different alerts\n'
	failures=$((failures + 1))
fi

# ── Scope filtering ────────────────────────────────────────────────────────
ks::heading "Scope"

# 4100 is the login shell in the capture; its descendants carry the intrusion,
# and the cron job reading /etc/shadow is outside the tree.
"$BINARY" --replay "$CAPTURE" --pid 4100 --output "$WORK/scoped.jsonl" >/dev/null 2>&1
ks::check_contains "--pid keeps the intrusion" "$WORK/scoped.jsonl" '"rule":"reverse-shell"'

if grep -q '"comm":"backup.sh"' "$WORK/scoped.jsonl"; then
	printf '  \033[1;31m✗\033[0m --pid leaked an out-of-tree process\n'
	failures=$((failures + 1))
else
	printf '  \033[1;32m✓\033[0m --pid excludes the unrelated cron job\n'
fi

# ── Result ─────────────────────────────────────────────────────────────────
printf '\n'

if [[ "$failures" -gt 0 ]]; then
	ks::fail "$failures check(s) failed — do not demo this build"
fi

ks::heading "Demo check passed: CLI, replay, dashboard, pacing and scope all verified"
