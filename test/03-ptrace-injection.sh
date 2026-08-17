#!/usr/bin/env bash
#
# Scenario 3 — Process Injection via ptrace  (rule: process-injection, T1055.008)
#
# FOR LOCAL VM / CONTAINER TESTING ONLY. See lib.sh for the full warning.
#
# WHAT THIS DOES
#   Starts a sacrificial `sleep` process, PTRACE_ATTACHes to it, reads one word
#   of its memory, then detaches and kills it.
#
# WHY THIS IS SAFE
#   The sacrificial process is one this script created purely to be attached to,
#   and it does nothing but sleep. No memory is *written* — the demo performs a
#   PEEKDATA (a read), and the write primitives (POKETEXT/POKEDATA/SETREGS) are
#   only named in comments, never issued. Attaching to a process you own is an
#   ordinary, unprivileged operation; it is the same thing gdb does.
#
# WHY IT ALERTS ANYWAY
#   PTRACE_ATTACH from a process not on the debugger allowlist is precisely the
#   signal the rule looks for. The tracer here is `python3`, which is not an
#   allowlisted debugger, so it alerts — exactly as a ptrace-based injector
#   would.
#
#   Try re-running this after adding python3 to the allowlist to see the
#   suppression work; that also demonstrates why comm-based allowlisting is a
#   usability feature rather than a security control (see the README).
#
# EXPECTED ALERTS
#   ptrace(PTRACE_ATTACH) → HIGH  T1055.008

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ks::banner "Scenario 3 — Process Injection via ptrace"
ks::require_cmd python3

# ptrace-attaching to a process you own normally requires either the same uid or
# CAP_SYS_PTRACE, and on many hosts the Yama LSM restricts it further to direct
# descendants. Report the setting rather than changing it — a test script that
# weakens a system-wide security control to make itself pass is a bad trade.
if [[ -r /proc/sys/kernel/yama/ptrace_scope ]]; then
	scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
	ks::step "yama ptrace_scope = $scope"
	if [[ "$scope" -ge 2 ]]; then
		ks::warn "ptrace_scope >= 2 restricts attaching; the syscall still fires and still alerts"
	fi
fi

ks::heading "Starting sacrificial target process"

# A plain sleep: no privileges, no state, nothing to corrupt.
sleep 60 &
target=$!
trap 'kill "$target" 2>/dev/null || true' EXIT

sleep 0.3
ks::step "target PID $target (sleep 60)"

ks::heading "Attaching with ptrace from a non-debugger process"

python3 - "$target" <<'PYTHON'
import ctypes
import ctypes.util
import os
import sys
import time

target = int(sys.argv[1])

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

PTRACE_PEEKDATA = 2
PTRACE_ATTACH   = 16
PTRACE_DETACH   = 17

# ── ATTACH — this is the syscall the rule fires on ───────────────────────────
rc = libc.ptrace(PTRACE_ATTACH, target, None, None)
if rc != 0:
    err = ctypes.get_errno()
    print(f"  \033[2m→\033[0m PTRACE_ATTACH failed (errno {err}: {os.strerror(err)})")
    print("  \033[2m→\033[0m the syscall was still made, so the alert still fires")
    sys.exit(0)

print(f"  \033[2m→\033[0m PTRACE_ATTACH to PID {target} succeeded")

# Wait for the target to stop so the subsequent read is well-defined.
try:
    os.waitpid(target, 0)
except ChildProcessError:
    time.sleep(0.2)

# ── PEEKDATA — a READ, deliberately. ─────────────────────────────────────────
# The write counterparts (PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_SETREGS) are
# what real code injection uses and what the rule also detects, but this script
# does not issue them: there is no reason to actually corrupt a process to prove
# the detection works.
ctypes.set_errno(0)
word = libc.ptrace(PTRACE_PEEKDATA, target, ctypes.c_void_p(0x1000), None)
print(f"  \033[2m→\033[0m PTRACE_PEEKDATA read returned {word} (read-only; nothing was modified)")

libc.ptrace(PTRACE_DETACH, target, None, None)
print(f"  \033[2m→\033[0m detached cleanly")
PYTHON

kill "$target" 2>/dev/null || true
wait "$target" 2>/dev/null || true
trap - EXIT

ks::heading "Done — expect 1 process-injection alert (PTRACE_ATTACH)"
