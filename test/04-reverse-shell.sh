#!/usr/bin/env bash
#
# Scenario 4 — Reverse Shell Syscall Chain  (rule: reverse-shell, T1059)
#
# FOR LOCAL VM / CONTAINER TESTING ONLY. See lib.sh for the full warning.
#
# WHAT THIS DOES
#   Runs both ends of a reverse shell on this machine:
#     • a listener bound to 127.0.0.1 only
#     • a "victim" that performs the canonical chain —
#           socket() → connect() → dup2(fd,0/1/2) → execve("/bin/sh")
#
#   The listener sends a single `exit` command and closes. The shell exits.
#
# WHY THIS IS SAFE
#   The listener binds to 127.0.0.1 explicitly — never 0.0.0.0, never a routable
#   address — so nothing outside this machine can reach it, and the "victim"
#   connects to 127.0.0.1 by literal address. The only command sent is `exit`.
#   The shell lives for a few milliseconds and is destroyed by its own first
#   instruction.
#
#   The entire exercise is a real reverse shell in *structure* and a no-op in
#   *effect*, which is exactly what is needed to prove the detection: the rule
#   matches on the syscall sequence, not on what the shell subsequently does.
#
# WHY IT ALERTS
#   None of the four syscalls is suspicious alone — every network client calls
#   socket() and connect(), every shell redirection calls dup2(). The rule fires
#   on the ordering within one process inside a 2-second window. This script is
#   the minimal thing that produces that ordering.
#
# EXPECTED ALERTS
#   socket → connect → dup2 → execve  → CRITICAL  T1059
#
# NOTE: run the agent WITHOUT --ignore-loopback, or this scenario is suppressed
#       by design.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ks::banner "Scenario 4 — Reverse Shell Syscall Chain"
ks::require_cmd python3

ks::heading "Starting loopback-only listener on 127.0.0.1:${DEMO_PORT}"

listener_log=$(mktemp /tmp/krnlsentry-listener.XXXXXX)
listener_py=$(mktemp /tmp/krnlsentry-listener-XXXXXX.py)
victim_py=$(mktemp /tmp/krnlsentry-victim-XXXXXX.py)
trap 'rm -f "$listener_log" "$listener_py" "$victim_py"' EXIT

cat >"$listener_py" <<'PYTHON'
# Loopback-only listener. Accepts one connection, sends "exit", closes.
# Bound to 127.0.0.1 explicitly — never INADDR_ANY.
import socket
import sys

port = int(sys.argv[1])

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))     # loopback only, by design
srv.listen(1)
srv.settimeout(15)

print(f"listening on 127.0.0.1:{port}", flush=True)

try:
    conn, addr = srv.accept()
except socket.timeout:
    print("no connection received", flush=True)
    sys.exit(1)

print(f"connection from {addr}", flush=True)

conn.settimeout(5)

# The one and only command sent to the shell. Nothing else is ever written.
conn.sendall(b"exit\n")

try:
    data = conn.recv(4096)
    if data:
        print(f"shell said: {data!r}", flush=True)
except socket.timeout:
    pass

conn.close()
srv.close()
print("listener done", flush=True)
PYTHON

cat >"$victim_py" <<'PYTHON'
# The "victim": the canonical reverse-shell syscall chain, and nothing more.
#
#   socket()  → allocate a TCP socket
#   connect() → dial the loopback listener
#   dup2()    → staple the socket onto stdin, stdout and stderr
#   execve()  → replace this process with a shell
#
# On arm64 there is no dup2 syscall and glibc routes os.dup2() through dup3();
# KrnlSentry probes both, which is why this works identically on x86_64 and on
# an Apple Silicon VM.
import os
import socket
import sys

port = int(sys.argv[1])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", port))     # loopback only, by design

fd = s.fileno()
os.dup2(fd, 0)
os.dup2(fd, 1)
os.dup2(fd, 2)

# execve completes the chain. The shell's first and only input is "exit".
os.execv("/bin/sh", ["/bin/sh"])
PYTHON

python3 "$listener_py" "$DEMO_PORT" >"$listener_log" 2>&1 &
listener=$!

# Wait for the listener to actually be bound before connecting, rather than
# sleeping a fixed amount and hoping.
for _ in $(seq 1 50); do
	grep -q "listening on" "$listener_log" 2>/dev/null && break
	sleep 0.1
done

grep -q "listening on" "$listener_log" 2>/dev/null || ks::fail "listener failed to start: $(cat "$listener_log")"
ks::step "listener ready"

ks::heading "Running the victim chain: socket → connect → dup2 ×3 → execve"

python3 "$victim_py" "$DEMO_PORT" || true

wait "$listener" 2>/dev/null || true

ks::step "listener output:"
sed 's/^/      /' "$listener_log"

rm -f "$listener_log" "$listener_py" "$victim_py"
trap - EXIT

ks::heading "Done — expect 1 CRITICAL reverse-shell alert"
