# Detection test scenarios

> **⚠ FOR LOCAL VM / CONTAINER TESTING ONLY.**
>
> These scripts exist to make KrnlSentry produce alerts so you can confirm each
> detection works. Run them in a throwaway VM or container — not because they
> are dangerous, but because they generate genuine security alerts, and a
> colleague investigating your fake reverse shell at 2am will not find it funny.

## Running everything

```bash
make build
sudo ./test/run-all.sh
```

`run-all.sh` starts the agent, runs all four scenarios, stops the agent, and
reports which rules fired. It **exits non-zero if any rule produced no alerts**,
so it works as a smoke test and not only as a demo.

```
  25 alerts written to /tmp/krnlsentry-e2e-alerts.jsonl

  ✓ privilege-escalation     6 alert(s)
  ✓ sensitive-file-access    17 alert(s)
  ✓ process-injection        1 alert(s)
  ✓ reverse-shell            1 alert(s)
```

In a container you need `--privileged` (or `CAP_BPF` + `CAP_PERFMON`) and
`tracefs` mounted; `run-all.sh` mounts it for you if it is missing.

```bash
docker run --rm --privileged -v "$PWD":/src krnlsentry-dev \
  bash -c "make build && ./test/run-all.sh"
```

## Running one scenario

Start the agent in one terminal and run a scenario in another:

```bash
sudo ./bin/krnlsentry                    # terminal 1
sudo ./test/04-reverse-shell.sh          # terminal 2
```

| Script | Rule | Expected |
| ------ | ---- | -------- |
| `01-sensitive-file.sh` | `sensitive-file-access` | 5–6 alerts, HIGH and MEDIUM |
| `02-privilege-escalation.sh` | `privilege-escalation` | 4 alerts, HIGH |
| `03-ptrace-injection.sh` | `process-injection` | 1 alert, HIGH |
| `04-reverse-shell.sh` | `reverse-shell` | 1 alert, CRITICAL |

`lib.sh` holds shared helpers and is sourced by the others; it is not runnable
on its own.

---

## Why each scenario is safe

This matters more than usual here, because the whole point is to imitate attack
behaviour. Each script is a *structural* imitation with no *effect*.

### 01 — Sensitive file access

Opens credential-bearing files read-only and closes them immediately.
`head -c 1` is enough: the rule matches the `openat()` syscall, not the read.
Nothing is copied, modified, or transmitted.

The SSH and AWS credential paths usually do not exist, so the script creates
decoys containing obvious placeholder text, opens them, and deletes them — and
it only deletes files it created, never a real key you already had.

### 02 — Privilege escalation

Drops to a throwaway unprivileged user (`ksdemo`, uid 4242) and from there calls
`setresuid(0,0,0)`, `setuid(0)`, `setresgid(0,0,0)` and `capset()`.

**All of these are expected to fail with `EPERM`.** An unprivileged process
cannot become root by asking; if it could, that would be a kernel bug rather
than a demo. No privilege is gained at any point.

They still alert because KrnlSentry traces syscall **entry**, before the kernel
decides whether to permit the call. That is a deliberate design property: an
attacker's *failed* escalation attempts are exactly what you want to see, since
they are the reconnaissance that precedes a successful one.

The `capset()` payload is all zeros — it requests no capabilities at all.

The setuid-execution part copies `/bin/true` (a program whose entire behaviour
is to exit successfully) to `/tmp`, sets the setuid bit, executes it as the demo
user, and deletes it. `setpriv` is preferred over `su`/`sudo` for the drop
because those are themselves setuid binaries and would generate their own
alerts, obscuring the one being demonstrated.

### 03 — ptrace injection

Starts a sacrificial `sleep 60`, `PTRACE_ATTACH`es to it, performs a
`PTRACE_PEEKDATA` — a **read** — then detaches and kills it.

The write primitives that real injection uses (`POKETEXT`, `POKEDATA`,
`SETREGS`) are named in comments and never issued. There is no reason to
actually corrupt a process to prove the detection works.

The script reports `/proc/sys/kernel/yama/ptrace_scope` but never changes it. A
test that weakens a system-wide security control to make itself pass is a bad
trade.

It alerts because the tracer is `python3`, which is not on the debugger
allowlist. Try adding `python3` to the allowlist and re-running to watch the
suppression work — which also demonstrates why `comm`-based allowlisting is a
usability feature and not a security control.

### 04 — Reverse shell

Runs both ends locally:

- a listener **bound to `127.0.0.1` explicitly** — never `0.0.0.0`, so nothing
  off this machine can reach it
- a victim that performs `socket()` → `connect("127.0.0.1")` → `dup2()` onto
  stdin/stdout/stderr → `execve("/bin/sh")`

The listener sends exactly one command — `exit` — and closes. The shell lives a
few milliseconds and is destroyed by its own first instruction.

This is a real reverse shell in structure and a no-op in effect, which is
precisely what is needed: the rule matches the syscall sequence, not what the
shell subsequently does.

> Run the agent **without** `--ignore-loopback` for this one, or it is
> suppressed by design.

On arm64 there is no `dup2` syscall and glibc routes `os.dup2()` through
`dup3()`. KrnlSentry probes both, so this behaves identically on x86_64 and on
an Apple Silicon VM.

---

## Cleaning up

The scripts remove what they create. The one thing left behind is the `ksdemo`
user (uid 4242), kept so repeated runs do not churn `/etc/passwd`. To remove it:

```bash
sudo userdel ksdemo && sudo groupdel ksdemo
```

## Troubleshooting

**No alerts at all** — check the agent actually attached. It logs
`eBPF probes attached tracepoints=N` at startup. If it exited instead, the error
will say whether it was privileges (`sudo`), BTF (`ls -l /sys/kernel/btf/vmlinux`),
or a missing `tracefs` mount.

**`tracepoints=14` rather than 15** — expected on arm64. That architecture has
no `dup2` syscall; `dup3` covers the same behaviour and the loader skips the
missing probe deliberately.

**Scenario 3 reports `PTRACE_ATTACH failed`** — Yama's `ptrace_scope` is
restricting it. The alert still fires, because the syscall was still made.

**Alerts appear but `run-all.sh` reports a rule as failed** — check
`/tmp/krnlsentry-e2e-alerts.jsonl` directly; the summary matches on the `rule`
field, so a renamed rule would show up this way.
