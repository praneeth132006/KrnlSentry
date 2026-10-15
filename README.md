# KrnlSentry

**eBPF-based syscall monitoring and threat detection for Linux.**

KrnlSentry attaches eBPF programs to syscall tracepoints, streams what it sees
into user space over a ring buffer, and flags behaviour associated with
privilege escalation, credential theft, process injection and reverse shells.
Alerts are tagged with [MITRE ATT&CK](https://attack.mitre.org/) technique IDs
and written as JSON Lines alongside a colour-coded terminal stream.

On top of the per-syscall rules sits an **attack-storyline correlator**: it
tracks process lineage, rolls every alert up to its ATT&CK *tactic*, and when one
process tree spans several distinct attacker goals it raises a single
`attack-chain` incident with the whole story in order. Every capture can also be
**replayed offline** — on any OS, without root — to regression-test rules or
retro-hunt old telemetry with new ones.

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
- [Attack storylines](#attack-storylines)
- [The live dashboard](#the-live-dashboard)
- [Replay and retro-hunting](#replay-and-retro-hunting)
- [Running the demo](#running-the-demo)
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
│                          │    │                                       │ │
│                          │    ▼                                       │ │
│                          │  Correlator ─ lineage → storyline →        │ │
│                          │    │          ATT&CK tactics → attack-chain│ │
│                          │    ▼                                       │ │
│                          │  Dedup ────── fold repeats per window      │ │
│                          │                                            │ │
│                          │  Pure functions. No eBPF. No I/O except    │ │
│                          │  an injected Stat for the SUID check.      │ │
│                          └───────────────────┬────────────────────────┘ │
│                                              │ detect.Alert             │
│                          ┌───────────────────▼────────────────────────┐ │
│                          │ output/                                    │ │
│                          │   JSONLSink   → alerts.jsonl (0600, append)│ │
│                          │   ConsoleSink → stdout, colour by severity │ │
│                          │   Dashboard   → full-screen live totals    │ │
│                          │                 (--dashboard, opt-in)      │ │
│                          └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Package layout

| Path            | Responsibility                                                          | Depends on            |
| --------------- | ----------------------------------------------------------------------- | --------------------- |
| `bpf/`          | eBPF C programs, shared event struct, minimal CO-RE header              | —                     |
| `ebpfloader/`   | Loading, attaching, ring buffer draining. **Only** user of cilium/ebpf  | `events`              |
| `events/`       | Canonical `Event` type, syscall argument decoding                       | stdlib only           |
| `detect/`       | Rule registry, process state tracker, the four detection rules, storyline correlator, deduplication | `events` |
| `output/`       | JSONL, console and dashboard sinks                                      | `detect`              |
| `cmd/krnlsentry/` | CLI, signal handling, pipeline wiring                                 | all of the above      |
| `test/`         | Safe demo scripts that trigger each detection                           | —                     |
| `testdata/captures/` | Golden `--verbose` captures replayed by the unit tests             | —                     |
| `internal/gencapture/` | Generator for the golden capture, built on the real decoder      | `events`              |

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

| `attack-chain` | ≥ `--chain-threshold` distinct ATT&CK tactics across one process tree (see [below](#attack-storylines)) | all of the above | CRITICAL |

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

## Attack storylines

Every rule above judges one process at one moment. Intrusions do not look like
that. They look like a login shell whose children, one after another, read
`~/.aws/credentials`, `ptrace` the shell, call `setuid(0)` and dial out — four
alerts, four PIDs, four rules, landing in a queue as four unrelated items.

The correlator puts them back together:

```
11:00:33.731  CRITICAL attack-chain   python3[4150]   uid=1000  T1552.001,T1055.008,T1548,T1059
              Multi-stage attack in the process tree of bash[4100]: Credential Access → Defense
              Evasion → Privilege Escalation → Execution → Command and Control
              (5 tactics, 4 alerts, 4 processes, 18.041s)
              ├─ +0ms      cat[4120]       Credential Access                openat /home/dev/.aws/credentials
              ├─ +6002ms   inject[4130]    Defense Evasion                  ptrace PTRACE_ATTACH → pid 4100
              ├─ +11005ms  exploit[4140]   Privilege Escalation             setuid(0)
              └─ +18041ms  python3[4150]   Execution + Command and Control  reverse shell to 10.13.37.9:4444
```

How it works:

1. **Lineage.** Every event — alerting or not — records `pid → (ppid, comm)`.
   The shell *between* two alerting children is usually the one process that
   never alerts, so lineage must come from the whole stream. Gaps (an ancestor
   that has not made a monitored syscall since startup) are filled from `/proc`.
2. **Session boundaries.** From an alerting process the correlator walks up the
   tree and stops *below* the process that owns the session — `sshd`,
   `systemd`, `containerd-shim`, `cron`, `tmux`, PID 1. Without this every
   process shares `init` as an ancestor and the host becomes one story; with it,
   each SSH login, container and daemon is its own scope.
3. **Storylines.** An alert joins the open storyline any process in its chain
   already belongs to. If its chain touches two storylines they merge, keeping
   the older id. Every alert carries a `storyline` field, so a SIEM can pivot
   from any one alert to everything related with one equality filter.
4. **Tactics, not volume.** Each alert's technique rolls up to an ATT&CK tactic
   (a completed reverse shell counts as both Execution and Command and
   Control). A storyline raises `attack-chain` when it spans
   `--chain-threshold` distinct tactics (default 3), and again each time it
   gains a new one. A process reading `/etc/shadow` fifty times is one tactic,
   however loud; three different attacker goals in one tree within minutes is
   the shape of an intrusion and almost never the shape of administration.

Storylines close after `--chain-window` (default 10 minutes) without a new
alert. Disable the whole thing with `--no-storyline`.

### Deduplication

A process opening `/etc/shadow` in a loop is one finding, not ten thousand.
Identical alerts — same rule, process, technique and distinguishing argument
(path, ptrace target, destination) — are folded for `--dedup-window` (default
5s). The window is fixed from the first emission, not sliding, so a steady loop
still resurfaces once per window; the resurfaced alert carries `suppressed: N`.
Folded alerts are still counted as evidence by the correlator.

---

## The live dashboard

`--dashboard` replaces the scrolling alert stream with a full-screen display
that repaints four times a second:

```
╭─ KrnlSentry v0.4.0 · LIVE · system-wide ─────────────────────────────────── 00:04:12 ╮
   events 182 417  alerts 7  folded 11  tracked 94  drops 0
╰──────────────────────────────────────────────────────────────────────────────────────╯

  SEVERITY ─────────────────────────────  RULES ────────────────────────────────────────
  CRITICAL ████████████████████████ 3     privilege-escalation                     1
  HIGH     ████████████████████████ 3     sensitive-file-access                    2
  MEDIUM   ████████                 1     process-injection                        1
  LOW                               0     reverse-shell                            1
                                          attack-chain                             2

  ATT&CK TACTICS ─────────────────────────────────────────────────────────────────────
   ● Execution   ● Privilege Escalation   ● Defense Evasion   ● Credential Access
   ● Command and Control

  TOP PROCESSES ──────────────────────────────────────────────────────────────────────
   exploit[4140] ×2   python3[4150] ×2   cat[4120] ×1   inject[4130] ×1

  ATTACK CHAIN   open storylines 2   chains raised 2 ─────────────────────────────────
    CRITICAL  Multi-stage attack in the process tree of bash[4100]: Credential Access…
   ├─ +0ms      cat[4120]        Credential Access     openat /home/dev/.aws/credentials
   ├─ +6002ms   inject[4130]     Defense Evasion       ptrace PTRACE_ATTACH → pid 4100
   ├─ +11005ms  exploit[4140]    Privilege Escalation  setuid(0)
   └─ +18041ms  python3[4150]    Execution + C2        reverse shell to 10.13.37.9:4444

  RECENT ALERTS   7 total ────────────────────────────────────────────────────────────
   11:00:33.731  CRITICAL  attack-chain          python3[4150]   T1059      Multi-stage…
   11:00:33.731  CRITICAL  reverse-shell         python3[4150]   T1059      Process "py…
   11:00:26.695  HIGH      privilege-escalation  exploit[4140]   T1548      Process "ex…
   11:00:21.692  HIGH      process-injection     inject[4130]    T1055.008  Process "in…

╰─ alerts → /var/log/krnlsentry.jsonl ───────────────────────────────────── Ctrl+C to stop ╯
```

It is **opt-in, and off by default, on purpose.** A line per alert on stdout
pipes, greps, redirects and reads fine over SSH; a full-screen display owns the
terminal and turns into garbage the moment anyone redirects it. So the default
stays the stream, and `--dashboard` refuses to start when stdout is not a
terminal — it says so and falls back rather than writing escape codes into
somebody's log file. (`--color` forces it anyway, which is what recording a
demo needs.)

What it buys when a human *is* watching is the thing a stream cannot give:
**standing totals**. Mid-incident the question is rarely "what was the last
alert" — it is how many, how bad, which rules, which processes, is a chain
forming, and *are we dropping events*. On a busy host all of that scrolls off
the top within seconds.

Four details worth knowing:

- **Zero rows are kept.** `CRITICAL 0` and `reverse-shell 0` are information:
  they say the rule is armed and quiet. An absent row cannot distinguish that
  from a rule that is not running.
- **Drops are never hidden.** Kernel ring-buffer drops and queue drops are
  summed into one figure that turns red the moment it is non-zero. A monitoring
  tool that quietly discarded events looks exactly like one that saw nothing.
- **`--min-severity` filters the feed, not the totals.** It is for quietening
  what competes for attention, not for unseeing the host, so the headline counts
  always describe the whole run.
- **The last frame is left on screen.** On Ctrl+C the display is not erased, so
  the run's totals sit above the shutdown summary where they can still be read.

Everything on screen is counted from the alerts the engine raised or read
through a metrics snapshot taken on the pipeline's own goroutine. The dashboard
is a `Sink` like any other and decides nothing: `detect/` remains the only
package with an opinion about what is suspicious.

---

## Replay and retro-hunting

`--verbose` writes every observed syscall to a lossless JSONL capture. `--replay`
feeds a capture back through exactly the same scope filter, engine and sinks:

```bash
sudo ./bin/krnlsentry --verbose --debug-output capture.jsonl     # record (Linux)
./bin/krnlsentry --replay capture.jsonl --output replayed.jsonl  # replay (any OS, no root)
make replay-demo                                                  # bundled intrusion capture
```

That makes three things possible that live tracing cannot do:

- **Rule development without eBPF.** The agent builds natively on macOS and
  Windows (the eBPF loader is replaced by a stub off Linux), so a new rule can
  be written and exercised against real captures on a laptop.
- **Retro-hunting.** Run a rule written today over last week's capture.
- **Reproducing false positives** from the reporter's capture instead of a
  description of it.

`testdata/captures/intrusion.jsonl` is a golden capture — an SSH session
carrying the intrusion above, interleaved with ordinary activity and a cron job
reading `/etc/shadow` in a loop — and `TestReplayGoldenCapture` pins exactly
which alerts, folds and attack chains it must produce.

---

## Running the demo

No root, no kernel, no Linux — the demo runs through the replay path, so it
works on the laptop you are presenting from:

```bash
make verify   # compile, unit tests, and an asserted end-to-end demo replay
make demo     # the bundled intrusion, paced, on the live dashboard
```

`make demo` replays `testdata/captures/intrusion.jsonl` against *its own clock*
(`--replay-speed`, default `2`, so the captured 34 seconds take about 17) with
the dashboard on. Pacing matters here: replayed as fast as the file can be read,
every alert and both attack chains land in a single frame, and the one thing
worth showing — a storyline assembling itself out of alerts that look unrelated
one at a time — is invisible. Watch for the moment the third tactic appears in
one process tree and the CRITICAL `attack-chain` row fills in its timeline.

```bash
make demo SPEED=1     # real time
make demo SPEED=8     # hurry up
make demo-live        # the real thing: live kernel, Linux, needs root
```

For a full presentation script — what to run, in what order, what to say about
each panel, the likely questions with answers, and a fallback for everything
that can fail in a room with a projector — see **[DEMO.md](DEMO.md)**. The
design rationale, diagrams, results and limitations are written up in
**[REPORT.md](REPORT.md)**.

Run `make verify` **before** demoing. It is the pre-flight check: it compiles,
runs the unit tests under `-race`, and then runs
[`test/demo-check.sh`](test/demo-check.sh), which exercises the actual binary —
CLI flags, the JSONL sink, scope filtering, pacing and the dashboard renderer —
and asserts the result rather than leaving it to be eyeballed. The unit tests
pin the engine; this pins the demo path around it.

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
sudo ./bin/krnlsentry --dashboard                      # live full-screen display
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
| `--dedup-window <duration>` | `5s` | Fold identical alerts into one per window (`0` disables) |
| `--no-storyline` | off | Disable storyline correlation and `attack-chain` alerts |
| `--chain-threshold <int>` | `3` | Distinct ATT&CK tactics in one process tree that raise `attack-chain` |
| `--chain-window <duration>` | `10m` | How long a storyline stays open after its last alert |
| `--replay <path>` | | Evaluate a `--verbose` capture instead of the live kernel (no root, any OS) |
| `--replay-speed <float>` | `0` | Pace a replay against the capture's own clock: `1` = real time, `2` = twice as fast, `0` = as fast as possible |
| `--dashboard` | off | Full-screen live display instead of the scrolling stream (needs a terminal; `--color` forces it) |
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
| `storyline` | Id shared by every alert from the same process tree (omitted with `--no-storyline`) |
| `suppressed` | Identical alerts folded into this one since it was last shown (omitted when zero) |
| `story` | `attack-chain` only: ordered steps, each with `offset_ms`, `pid`, `comm`, `rule`, `mitre_id`, `tactic`, `summary` |

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
  ✓ attack-chain             2 alert(s)
```

It exits non-zero if any rule fails to fire, or if the correlator fails to
stitch the four scenarios — all descendants of the runner — into an attack
chain.

> **Run these in a throwaway VM or container only.** They are safe by
> construction — the privilege-escalation syscalls are *expected to fail with
> `EPERM`* (KrnlSentry traces syscall entry, so denied attempts alert exactly
> like successful ones), the ptrace demo only reads, and the reverse shell binds
> and dials `127.0.0.1` exclusively and sends a single `exit`. But they generate
> genuine security alerts, and a colleague investigating your fake reverse shell
> at 2am will not find it funny.

See [test/README.md](test/README.md) for what each scenario does.

The scenario scripts need Linux and root. For everything that does not —
the CLI, the JSONL contract, scope filtering, replay pacing and the dashboard —
`make verify` runs the unit tests plus `test/demo-check.sh` on any OS:

```bash
make verify
```

```
  ✓ privilege-escalation     1 alert(s)
  ✓ sensitive-file-access    2 alert(s)
  ✓ process-injection        1 alert(s)
  ✓ reverse-shell            1 alert(s)
  ✓ attack-chain             2 alert(s)
  ✓ reverse shell confirms the socket fd
  ✓ alert log is mode 0600
  ✓ dashboard declines a non-terminal
  ✓ pacing does not change the alerts
  ✓ --pid excludes the unrelated cron job
```

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

### Storyline caveats

**Session boundaries are `comm`-based.** A process that names itself `sshd`
splits its own storyline in two. That costs correlation, not detection: every
underlying alert still fires.

**PIDs are reused.** Lineage and storylines are keyed by PID within the chain
window. On a host that wraps its PID space inside ten minutes, an unrelated
process could inherit a storyline. Exact fork/exit tracking (roadmap item 5)
closes this.

**Replay checks setuid bits on the replaying host.** The setuid-exec rule
`stat`s the executed path; under `--replay` that is the local filesystem, not
the captured one.

### Roadmap

1. eBPF-side PID and cgroup filtering (biggest performance win)
2. Container/namespace awareness — cgroup id and namespace-correct PIDs
3. Binary-identity verification to replace `comm` allowlisting
4. Full capability diffing for `capset()`
5. `sched_process_fork`/`exit` probes for exact process-tree tracking
6. ~~Alert deduplication and rate limiting~~ — done (`--dedup-window`)
7. LSM hooks (`bpf_lsm`) for resolved-path matching

---

## Documentation

| Document | What it covers |
| -------- | -------------- |
| [DEMO.md](DEMO.md) | Presentation script: pre-flight, five acts, what to point at, Q&A, failure fallbacks |
| [REPORT.md](REPORT.md) | Project report: architecture diagrams, design decisions and their justification, results, metrics, limitations, roadmap |
| [CHANGELOG.md](CHANGELOG.md) | Release notes, Keep a Changelog format |
| [test/README.md](test/README.md) | What each detection scenario does and how to run one |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow |

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Adding a detection rule is deliberately cheap: write one function in `detect/`,
register it in `engine.go`, add a table test, and map any new ATT&CK technique
to its tactic in `storyline.go` (a test fails if you forget). You should not need to touch
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
