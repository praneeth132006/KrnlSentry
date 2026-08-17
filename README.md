# KrnlSentry

**eBPF-based syscall monitoring and threat detection for Linux.**

KrnlSentry attaches eBPF programs to syscall tracepoints, streams what it sees
into user space over a ring buffer, and flags behaviour associated with
privilege escalation, credential theft, process injection and reverse shells.
Alerts are tagged with [MITRE ATT&CK](https://attack.mitre.org/) technique IDs
and written as JSON Lines alongside a colour-coded terminal stream.

```
15:04:23.117  CRITICAL  reverse-shell    python3[22116]    uid=0  T1059
              Process "python3" (PID 22116, UID 0) completed socket → connect to
              10.13.37.9:4444 → dup2(stderr,stdin,stdout) → execve("/bin/sh") in 1ms
              — reverse shell pattern
              chain_socket_fd_confirmed=true chain_duration_ms=1
```

> **Status:** working, tested end to end, and built as a learning project for
> detection engineering. It is deliberately explicit about what it does *not*
> catch — see [Limitations](#limitations--future-work). Do not deploy it as your
> only line of defence.

---

## Table of contents

- [Why eBPF](#why-ebpf)
- [Architecture](#architecture)
- [Detections](#detections)
- [Requirements](#requirements)
- [Building](#building)
- [Usage](#usage)
- [Output format](#output-format)
- [Testing the detections](#testing-the-detections)
- [Limitations & future work](#limitations--future-work)
- [Contributing](#contributing)
- [License](#license)

---

## Why eBPF

Watching syscalls from user space means `ptrace` (which halts the target and is
trivially detected) or `auditd` (which is a firehose with a rigid rule
language). eBPF runs the filtering *inside the kernel*, at the syscall boundary,
with no context switch per event and no way for the traced process to opt out.

This project uses **libbpf + CO-RE** rather than BCC. The difference matters in
practice: BCC compiles its kernel programs at runtime, so every machine you
deploy to needs clang, LLVM and matching kernel headers installed. CO-RE
compiles once, embeds the BTF relocations in the object, and libbpf patches
struct offsets against the running kernel's own type information at load time.
The result is a **single static Go binary** that runs on any 5.8+ kernel with
BTF — nothing to install on the target.

---

## Architecture

The single most important property of this codebase is that **the detection
logic knows nothing about eBPF**. Rules operate on a plain `events.Event`
struct, which means the entire detection surface is unit-testable with struct
literals — no kernel, no root, no privileged CI runner.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ KERNEL SPACE                                     bpf/krnlsentry.bpf.c   │
│                                                                         │
│   tracepoint/syscalls/…                                                 │
│     sys_enter_execve      sys_enter_ptrace     sys_enter_socket         │
│     sys_enter_execveat    sys_enter_setuid     sys_exit_socket          │
│     sys_enter_openat      sys_enter_setgid     sys_enter_connect        │
│     sys_enter_capset      sys_enter_setresuid  sys_exit_connect         │
│                           sys_enter_setresgid  sys_enter_dup2 / dup3    │
│                                                                         │
│   Each probe extracts: pid, tgid, uid, gid, ppid, comm, syscall args,   │
│   timestamp. Strings are copied with bpf_probe_read_user_str().         │
│                                                                         │
│   NO policy here — no path matching, no allowlists, no filtering.       │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │  BPF_MAP_TYPE_RINGBUF (256 KiB)
                                 │  global ordering, reserve/commit
┌────────────────────────────────▼────────────────────────────────────────┐
│ USER SPACE                                                              │
│                                                                         │
│  ┌───────────────┐   raw bytes    ┌──────────────┐   events.Event       │
│  │ ebpfloader/   │───────────────▶│  events/     │────────────┐         │
│  │               │                │              │            │         │
│  │ load, attach, │                │ decode args, │            │         │
│  │ drain ringbuf │                │ name flags   │            │         │
│  │ cilium/ebpf   │                │ stdlib only  │            │         │
│  └───────────────┘                └──────────────┘            │         │
│                                                               ▼         │
│                          ┌────────────────────────────────────────────┐ │
│                          │ detect/                                    │ │
│                          │                                            │ │
│                          │  Tracker ──── bounded per-PID history      │ │
│                          │    │          (depth 32, TTL 30s)          │ │
│                          │    ▼                                       │ │
│                          │  Rules: privesc · sensitive-file ·         │ │
│                          │         ptrace-injection · reverse-shell   │ │
│                          │                                            │ │
│                          │  Pure functions. No eBPF. No I/O except    │ │
│                          │  an injected Stat for the SUID check.      │ │
│                          └───────────────────┬────────────────────────┘ │
│                                              │ detect.Alert             │
│                          ┌───────────────────▼────────────────────────┐ │
│                          │ output/                                    │ │
│                          │   JSONLSink  → alerts.jsonl (0600, append) │ │
│                          │   ConsoleSink → stdout, colour by severity │ │
│                          └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Package layout

| Path            | Responsibility                                                          | Depends on            |
| --------------- | ----------------------------------------------------------------------- | --------------------- |
| `bpf/`          | eBPF C programs, shared event struct, minimal CO-RE header              | —                     |
| `ebpfloader/`   | Loading, attaching, ring buffer draining. **Only** user of cilium/ebpf  | `events`              |
| `events/`       | Canonical `Event` type, syscall argument decoding                       | stdlib only           |
| `detect/`       | Rule registry, process state tracker, the four detection rules          | `events`              |
| `output/`       | JSONL and console sinks                                                 | `detect`              |
| `cmd/krnlsentry/` | CLI, signal handling, pipeline wiring                                 | all of the above      |
| `test/`         | Safe demo scripts that trigger each detection                           | —                     |

### Design decisions worth knowing

**Ring buffer, not perf buffer.** `BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) delivers
events in **global order** across CPUs. A per-CPU perf buffer does not, and the
reverse-shell rule is a *sequence* detector — out-of-order delivery would make
it silently wrong rather than merely untidy. The ring buffer's reserve/commit
API also lets the kernel program fill the event in place, which matters because
a 544-byte event does not fit on BPF's 512-byte stack.

**Tracepoints, not kprobes.** Syscall tracepoints are a stable kernel ABI.
kprobes on `sys_*` symbols break across kernel versions and differ between
architectures (`__x64_sys_openat` vs `__arm64_sys_openat`).

**No policy in the kernel.** Everything in the BPF program runs in the syscall
hot path with the calling process blocked, under a verifier that forbids
unbounded loops. String matching and rule evaluation fit that environment
badly. Keeping policy in Go means a new rule is a function with a unit test
rather than a kernel program that has to be re-argued with the verifier. The
cost — every matching syscall produces an event whether or not a rule cares —
is stated in [Limitations](#limitations--future-work).

**A hand-written `vmlinux.h`.** `bpf/vmlinux_min.h` declares the ~4 kernel types
this project touches instead of vendoring the 3.5 MB generated header. This is
still full CO-RE: `__attribute__((preserve_access_index))` makes libbpf resolve
field offsets from the running kernel's BTF at load time. The benefit is that
**building needs no BTF on the build host**, which is what makes the project
buildable in a container on a Mac.

---

## Detections

| Rule | Trigger | ATT&CK | Severity |
| ---- | ------- | ------ | -------- |
| `privilege-escalation` | `setuid(0)` / `setresuid(0,…)` from a non-root process | [T1548](https://attack.mitre.org/techniques/T1548/) | HIGH |
| | `setgid(0)` / `setresgid(0,…)` from a non-root process | T1548 | HIGH |
| | `capset()` from a non-root process | T1548 | HIGH |
| | `execve()` of a setuid/setgid binary by a non-root user | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | HIGH |
| `sensitive-file-access` | `openat()` of `/etc/shadow`, `/etc/gshadow` (+ `-` backups) | [T1003.008](https://attack.mitre.org/techniques/T1003/008/) | HIGH |
| | `openat()` of `/proc/<pid>/mem` | [T1003.007](https://attack.mitre.org/techniques/T1003/007/) | HIGH |
| | `openat()` of `/proc/<pid>/maps` | T1003.007 | MEDIUM |
| | `openat()` of `/etc/sudoers`, `/etc/sudoers.d/*` | [T1552](https://attack.mitre.org/techniques/T1552/) | MEDIUM |
| | `openat()` of `~/.ssh/id_*`, `~/.gnupg/` secret keys | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | MEDIUM |
| | `openat()` of `~/.aws/credentials`, `~/.docker/config.json`, `~/.kube/config` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | MEDIUM |
| `process-injection` | `ptrace()` with `ATTACH`, `SEIZE`, `POKETEXT`, `POKEDATA`, `POKEUSER`, `SETREGS`, `SETREGSET`, `SETFPREGS` from a non-allowlisted process | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | HIGH |
| `reverse-shell` | `socket` → `connect` → `dup2`/`dup3` onto ≥2 standard fds → `execve`, within one PID inside a 2s window | [T1059](https://attack.mitre.org/techniques/T1059/) | CRITICAL |

Run `krnlsentry --list-rules` for the same table from the binary itself.

### What makes the reverse-shell rule interesting

None of `socket()`, `connect()`, `dup2()` or `execve()` is suspicious. Every
network client makes the first two; every shell redirection makes the third.
The detection is entirely about **ordering within one process in a short
window**. KrnlSentry additionally captures the fd that `socket()` returned (via
a `sys_exit` probe) and confirms it is the same fd being duplicated onto
stdin/stdout/stderr — reported as `chain_socket_fd_confirmed`, which rules out
the coincidence of a program that opens a socket and separately redirects a file.

---

## Requirements

**Kernel 5.8 or newer**, with:

| Config | Why |
| ------ | --- |
| `CONFIG_BPF_SYSCALL=y` | Load BPF programs at all |
| `CONFIG_DEBUG_INFO_BTF=y` | CO-RE relocation against the running kernel |
| `CONFIG_BPF_EVENTS=y` | Attach BPF to tracepoints |
| `CONFIG_FTRACE=y` / `CONFIG_TRACEPOINTS=y` | The tracepoints themselves |

Check your kernel:

```bash
grep -E 'CONFIG_(BPF_SYSCALL|DEBUG_INFO_BTF|BPF_EVENTS)=' /boot/config-$(uname -r) && ls -l /sys/kernel/btf/vmlinux
```

If `/sys/kernel/btf/vmlinux` exists and is readable, you are fine. Ubuntu
22.04 and 24.04 ship this by default.

**Privileges:** root, or `CAP_BPF` + `CAP_PERFMON` (`CAP_SYS_ADMIN` on kernels
before 5.8).

**To build:** Go 1.25+, clang 12+, `libbpf-dev`. Or just Docker — see below.

---

## Building

### With Docker (recommended, and required on macOS/Windows)

eBPF is Linux-only, so on any other host the dev container is the only way to
build. It works identically on Apple Silicon and x86_64.

```bash
make docker-build
make docker-make TARGET=all
```

For an interactive shell in the toolchain:

```bash
make docker-shell
```

> **macOS note.** [Colima](https://github.com/abiosoft/colima) is a better host
> than Docker Desktop here: its Lima VM runs a stock Ubuntu kernel with
> `CONFIG_DEBUG_INFO_BTF=y`, so you can actually *run* the agent and not only
> compile it. Docker Desktop's LinuxKit kernel often lacks BTF.
>
> ```bash
> colima start --cpu 4 --memory 6
> ```

### Natively on Linux

```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev make
make build          # → ./bin/krnlsentry
make test
```

### What the build actually does

```
bpf/krnlsentry.bpf.c
        │  clang -target bpf -O2 -g   (via bpf2go)
        ▼
krnlsentry_{arm64,x86}_bpfel.o        compiled BPF ELF with BTF
        │  bpf2go
        ▼
krnlsentry_{arm64,x86}_bpfel.go       Go bindings + the .o embedded as bytes
        │  go build
        ▼
bin/krnlsentry                        single static binary
```

The generated `*_bpfel.go` files are **not committed** — they embed a compiled
ELF, so a stale one would be invisible in code review and would silently ship
yesterday's kernel code. `make build` regenerates them.

`-O2` is mandatory rather than an optimisation preference: the verifier rejects
the unoptimised output clang emits at `-O0`.

---

## Usage

```bash
sudo ./bin/krnlsentry                                  # system-wide
sudo ./bin/krnlsentry --pid 1234                       # one process tree
sudo ./bin/krnlsentry --rules reverse-shell            # one rule
sudo ./bin/krnlsentry --output /var/log/krnlsentry.jsonl --min-severity HIGH
sudo ./bin/krnlsentry --verbose                        # log every syscall too
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--pid <int>` | `0` (all) | Monitor only this PID and its descendants |
| `--output <path>` | `./alerts.jsonl` | JSONL alert log |
| `--rules <list>` | all | Comma-separated subset of rules |
| `--verbose` | off | Log every observed syscall to a separate debug log |
| `--debug-output <path>` | `./debug.jsonl` | Where `--verbose` writes |
| `--min-severity <level>` | `LOW` | Console threshold; the JSONL log always gets everything |
| `--window <duration>` | `2s` | Reverse-shell chain window |
| `--ignore-loopback` | off | Suppress reverse-shell alerts to `127.0.0.0/8` |
| `--ignore-self-proc` | off | Suppress alerts for a process reading its own `/proc` entry |
| `--stats-interval <duration>` | off | Periodic throughput logging |
| `--no-color` / `--color` | auto | Override terminal detection (`NO_COLOR` is honoured) |
| `--list-rules` | | Print the rule table and exit |

Stop with **Ctrl+C**. The agent detaches every probe, flushes and `fsync`s the
alert log, and prints a summary including any dropped events.

### Running in Docker

```bash
make docker-run
```

which is shorthand for:

```bash
docker run --rm -it --privileged --pid=host \
  -v "$PWD":/src -v /sys/kernel/debug:/sys/kernel/debug:ro \
  krnlsentry-dev bash -c "make build && ./bin/krnlsentry"
```

`--privileged` is a blunt instrument. On kernels that support it, prefer:

```bash
docker run --rm -it --cap-add CAP_BPF --cap-add CAP_PERFMON --pid=host …
```

Tracepoint attachment needs `tracefs`; inside a container mount it with
`mount -t tracefs tracefs /sys/kernel/tracing`.

---

## Output format

One JSON object per line, append-only, mode `0600`.

```json
{"timestamp":"2026-08-17T10:22:31.854Z","pid":4821,"tid":4821,"ppid":4802,"comm":"bash","uid":1000,"syscall":"setuid","args":{"target_uid":"0"},"mitre_id":"T1548","mitre_technique":"Abuse Elevation Control Mechanism","severity":"HIGH","description":"Process \"bash\" (PID 4821, UID 1000) called setuid(0) — possible privilege escalation attempt","rule":"privilege-escalation"}
```

| Field | Notes |
| ----- | ----- |
| `timestamp` | RFC 3339, wall clock. Rules measure elapsed time with the kernel's monotonic clock instead |
| `pid` | The **process** id (kernel `tgid`) — what `ps` shows |
| `tid` | The **thread** id (kernel `pid`) |
| `args` | Decoded, syscall-specific. Flags are symbolic (`O_RDONLY\|O_CLOEXEC`), not numeric |
| `severity` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `rule` | Which rule fired — stable, safe to build filters on |

JSONL rather than a JSON array so the file is valid at every instant: a tool
killed with `SIGKILL` leaves a complete file minus at most one line, whereas an
array without its closing bracket is unparseable. It also streams:

```bash
tail -f alerts.jsonl | jq -c 'select(.severity=="CRITICAL")'
```

---

## Testing the detections

`test/` contains four scenario scripts and a runner that doubles as an
end-to-end smoke test.

```bash
sudo ./test/run-all.sh
```

```
  25 alerts written to /tmp/krnlsentry-e2e-alerts.jsonl

  ✓ privilege-escalation     6 alert(s)
  ✓ sensitive-file-access    17 alert(s)
  ✓ process-injection        1 alert(s)
  ✓ reverse-shell            1 alert(s)
```

It exits non-zero if any rule fails to fire.

> **Run these in a throwaway VM or container only.** They are safe by
> construction — the privilege-escalation syscalls are *expected to fail with
> `EPERM`* (KrnlSentry traces syscall entry, so denied attempts alert exactly
> like successful ones), the ptrace demo only reads, and the reverse shell binds
> and dials `127.0.0.1` exclusively and sends a single `exit`. But they generate
> genuine security alerts, and a colleague investigating your fake reverse shell
> at 2am will not find it funny.

See [test/README.md](test/README.md) for what each scenario does.

---

## Limitations & future work

Stated plainly, because a detection whose limits you cannot articulate is a
detection you cannot rely on.

### Known evasions

**`comm`-based debugger allowlisting is spoofable.** The ptrace rule exempts
processes named `gdb`, `strace`, `lldb`. `comm` is just the first 15 bytes of
the executable name, so anything that copies itself to `/tmp/gdb` walks past
this check. The allowlist buys *usability* — one debugging session otherwise
produces thousands of alerts — not security. A real product would verify the
binary rather than its name: resolve `/proc/<pid>/exe` and check a signature or
an IMA/EVM measurement.

**Path matching happens on the unresolved string.** `openat("/etc/shadow")` is
caught; a symlink to it, a bind mount, a relative path after `chdir`, or reading
the underlying block device is not. Closing this properly means hooking at the
VFS or LSM layer where the resolved inode is available.

**Only `openat()` is watched, not `open()`.** Modern glibc routes `open()`
through `openat()`, so ordinary programs are covered, but a static binary
issuing a raw `open()` syscall is missed.

**`id_rsa.pub` matches the private-key pattern.** Accepted: excluding `.pub`
would also miss `id_rsa.old` and `id_rsa.bak`, which *do* contain key material.
Over-matching a public key is the better failure.

**Time-of-check/time-of-use on the SUID check.** The executed path is `stat`ed
after the `execve` is observed, so a binary replaced in between is reported as
whatever it is now.

**Relative execve paths are skipped.** Resolving one needs the process's `cwd`,
and by the time it could be read the exec has already replaced the image.
Guessing would produce confidently wrong alerts.

### Coverage gaps

**No container or namespace awareness.** This is the most significant gap. The
kernel reports PIDs from the initial namespace, but syscall *arguments* (like
`ptrace`'s target PID) are in the *caller's* namespace. An alert can therefore
carry `pid: 22100` (host view) alongside `target_pid: 71` (container view) —
two different namespaces in one record. There is no cgroup or container ID on
events, so you cannot answer "which container did this come from?". Fixing this
means reading `task->nsproxy->pid_ns_for_children` and the cgroup id via CO-RE.

**No eBPF-side filtering.** Every matching syscall on the system produces a
544-byte event even when `--pid` will immediately discard it. On a busy host
`openat` alone can be hundreds of thousands of events per second. Moving the PID
filter into a BPF map consulted inside each probe is the single highest-value
improvement available, and is deliberately deferred so the collection layer
stays policy-free and swappable.

**`capset()` is not diffed.** Any `capset()` from a non-root process alerts.
Deciding whether it actually *raises* privileges requires comparing the
requested set against the process's bounding set (`task->cred->cap_bset` via
CO-RE) — otherwise a process legitimately *dropping* capabilities is
indistinguishable from one raising them.

**IPv6 destinations record family and port but not the address.** There is no
room for a 16-byte address in the fixed-size event.

**No `sched_process_fork` probe.** `--pid` descendant tracking learns about new
children from their first syscall's PPID, so a grandchild whose parent exited
before we saw it is re-parented to init and lost.

**Strings are truncated** — paths at 256 bytes, argv at 3 entries × 64 bytes.

**No aggregation or rate limiting.** A process opening `/etc/shadow` in a loop
produces one alert per open.

### Roadmap

1. eBPF-side PID and cgroup filtering (biggest performance win)
2. Container/namespace awareness — cgroup id and namespace-correct PIDs
3. Binary-identity verification to replace `comm` allowlisting
4. Full capability diffing for `capset()`
5. `sched_process_fork`/`exit` probes for exact process-tree tracking
6. Alert deduplication and rate limiting
7. LSM hooks (`bpf_lsm`) for resolved-path matching

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Adding a detection rule is deliberately cheap: write one function in `detect/`,
register it in `engine.go`, and add a table test. You should not need to touch
the eBPF code unless you need a syscall that is not yet probed.

Security issues: see [SECURITY.md](SECURITY.md).

---

## License

[Apache License 2.0](LICENSE).

The eBPF programs under `bpf/` are dual-licensed `GPL-2.0 OR BSD-3-Clause` and
declare `"Dual BSD/GPL"` to the kernel. That is not a formality:
`bpf_probe_read_user_str()` — the helper this entire project is built around —
is `gpl_only`, and declaring anything else makes every probe fail to load with
`-EACCES`.
