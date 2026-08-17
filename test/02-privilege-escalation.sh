#!/usr/bin/env bash
#
# Scenario 2 — Privilege Escalation  (rule: privilege-escalation, T1548)
#
# FOR LOCAL VM / CONTAINER TESTING ONLY. See lib.sh for the full warning.
#
# WHAT THIS DOES
#   Drops to an unprivileged demo user and, from there:
#     a) calls setresuid(0,0,0)  — asks the kernel to make it root
#     b) calls setuid(0)         — the textbook version of the same request
#     c) calls capset()          — attempts to change its capability set
#     d) execve()s a setuid-root binary
#
# WHY THIS IS SAFE — AND WHY IT STILL WORKS
#   (a), (b) and (c) are *expected to fail with EPERM*. An unprivileged process
#   cannot become root by asking; if it could, this would be a kernel bug rather
#   than a demo. No privilege is actually gained at any point.
#
#   They still produce alerts because KrnlSentry traces syscall *entry*, before
#   the kernel has decided whether to permit the call. That is a deliberate
#   design property, not a coincidence: an attacker's failed escalation attempts
#   are exactly what you want to see, since they are the reconnaissance that
#   precedes a successful one.
#
#   (d) is a genuine setuid execution, but of a harmless binary (a copy of
#   /bin/true, or /usr/bin/id) that does nothing but exit. It is removed
#   afterwards.
#
# EXPECTED ALERTS
#   setresuid(0,0,0) from uid 4242  → HIGH  T1548
#   setuid(0)        from uid 4242  → HIGH  T1548
#   capset()         from uid 4242  → HIGH  T1548
#   execve of setuid binary          → HIGH  T1548.001

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ks::banner "Scenario 2 — Privilege Escalation"
ks::require_root
ks::require_cmd python3
ks::ensure_demo_user

# ── (a)(b)(c) credential-changing syscalls from an unprivileged process ──────
#
# Done in Python via ctypes so that the syscalls are made directly, with no
# intermediate setuid helper (like sudo or su) muddying which process made the
# call. os.setuid() below runs *as root* and is correctly ignored by the rule —
# root dropping privileges is normal and alerting on it would drown the signal.
ks::heading "Credential syscalls from an unprivileged process"

python3 - "$DEMO_UID" "$DEMO_GID" <<'PYTHON'
import ctypes
import ctypes.util
import os
import sys

demo_uid = int(sys.argv[1])
demo_gid = int(sys.argv[2])

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

pid = os.fork()
if pid:
    _, status = os.waitpid(pid, 0)
    sys.exit(0)

# ── child ────────────────────────────────────────────────────────────────────
# Drop to the demo user. This setgid/setuid pair is made BY ROOT and is exactly
# the legitimate privilege-drop pattern the rule deliberately ignores.
os.setgid(demo_gid)
os.setuid(demo_uid)

assert os.getuid() == demo_uid, "failed to drop privileges"
print(f"  \033[2m→\033[0m now running as uid {os.getuid()}")

# (a) setresuid(0, 0, 0) — the call real exploit payloads use, because it sets
#     all three uids at once and leaves no saved uid to fall back to.
rc = libc.setresuid(0, 0, 0)
print(f"  \033[2m→\033[0m setresuid(0,0,0) returned {rc} "
      f"({'EPERM as expected' if rc != 0 else 'UNEXPECTEDLY SUCCEEDED'})")

# (b) setuid(0) — the textbook form.
rc = libc.setuid(0)
print(f"  \033[2m→\033[0m setuid(0) returned {rc} "
      f"({'EPERM as expected' if rc != 0 else 'UNEXPECTEDLY SUCCEEDED'})")

# (c) setresgid(0, 0, 0) — the group-identity equivalent.
rc = libc.setresgid(0, 0, 0)
print(f"  \033[2m→\033[0m setresgid(0,0,0) returned {rc} "
      f"({'EPERM as expected' if rc != 0 else 'UNEXPECTEDLY SUCCEEDED'})")

# (d) capset() — attempt to grant ourselves capabilities. The header requests
#     the v3 capability ABI; the data payload is all zeros, so even in the
#     impossible case that this succeeded it would grant nothing.
class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]

hdr = CapHeader(0x20080522, 0)   # _LINUX_CAPABILITY_VERSION_3
data = (CapData * 2)()           # zeroed: requests no capabilities at all

rc = libc.capset(ctypes.byref(hdr), ctypes.byref(data))
print(f"  \033[2m→\033[0m capset() returned {rc}")

os._exit(0)
PYTHON

# ── (d) execve of a setuid-root binary as an unprivileged user ───────────────
ks::heading "Executing a setuid-root binary as an unprivileged user"

# A copy of a harmless system binary. /bin/true does nothing and exits 0; if it
# is unavailable, /usr/bin/id merely prints identity information. Neither can
# alter the system even while carrying the setuid bit.
suid_src=""
for candidate in /bin/true /usr/bin/true /usr/bin/id /bin/id; do
	if [[ -x "$candidate" ]]; then
		suid_src="$candidate"
		break
	fi
done

[[ -n "$suid_src" ]] || ks::fail "no suitable harmless binary found to copy"

suid_demo=/tmp/krnlsentry-suid-demo
trap 'rm -f "$suid_demo"' EXIT

cp "$suid_src" "$suid_demo"
chown root:root "$suid_demo"
chmod 4755 "$suid_demo"

ks::step "created $suid_demo (setuid root, copy of $suid_src)"
ks::step "executing it as uid $DEMO_UID"

# setpriv is preferred over su/sudo: those are themselves setuid binaries and
# would generate their own alerts, obscuring the one we are demonstrating.
if command -v setpriv >/dev/null 2>&1; then
	setpriv --reuid="$DEMO_UID" --regid="$DEMO_GID" --clear-groups "$suid_demo" >/dev/null 2>&1 || true
else
	python3 -c "
import os, sys
pid = os.fork()
if pid == 0:
    os.setgid($DEMO_GID); os.setuid($DEMO_UID)
    os.execv('$suid_demo', ['$suid_demo'])
os.waitpid(pid, 0)
" || true
fi

rm -f "$suid_demo"
trap - EXIT

ks::heading "Done — expect 4 privilege-escalation alerts"
