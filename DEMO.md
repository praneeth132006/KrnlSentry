# Demonstrating KrnlSentry

A complete, rehearsed script for a 10–15 minute demonstration, plus the
fallbacks for everything that can go wrong in a room with a projector.

**The one thing to know before you start:** the whole demo runs through
`--replay` on your own laptop. No root, no kernel, no Linux, no network, no
container. If the lab machine, the VM, the Wi-Fi or the USB-C adapter betrays
you, the demo still runs.

---

## Contents

- [Before the demo](#before-the-demo)
- [The 60-second version](#the-60-second-version)
- [Full demo script](#full-demo-script)
- [What to point at on the dashboard](#what-to-point-at-on-the-dashboard)
- [The live kernel demo (optional)](#the-live-kernel-demo-optional)
- [Likely questions, with answers](#likely-questions-with-answers)
- [If something breaks](#if-something-breaks)
- [One-page cheat sheet](#one-page-cheat-sheet)

---

## Before the demo

### The night before

```bash
cd /path/to/KrnlSentry
make verify
```

This is the pre-flight check. It compiles, runs all 88 unit tests under the race
detector, and then runs `test/demo-check.sh`, which drives the real binary
through the CLI, the JSONL sink, the dashboard renderer, replay pacing and
`--pid` scope filtering, asserting each result. It takes under a minute and it
ends with:

```
── Demo check passed: CLI, replay, dashboard, pacing and scope all verified
```

If it does not say that, **do not demo that build** — the output names the exact
check that failed.

### Ten minutes before

1. **Terminal geometry.** The dashboard adapts, but it looks best at
   **110×44 or larger**. Set the font size so the back row can read it, *then*
   maximise, then check:

   ```bash
   echo "$(tput cols)x$(tput lines)"     # want ≥ 100 x ≥ 30
   ```

2. **Warm the Go build cache** so the first `make demo` is instant rather than
   spending eight seconds compiling in front of an audience:

   ```bash
   go build ./... && make demo SPEED=50
   ```

3. **Clear the screen and your shell history noise.** The dashboard paints from
   the top of the terminal; a scrollback full of build output is distracting.

   ```bash
   clear
   ```

4. **Close anything that can interrupt**: notifications, Slack, auto-updaters.

### Check you have these four commands memorised

```bash
make demo              # the main event
make demo SPEED=1      # real time, if asked
make verify            # the tests, if asked
./bin/krnlsentry --list-rules
```

---

## The 60-second version

If you are given one minute, run exactly this and say exactly this:

```bash
make demo SPEED=4
```

> "KrnlSentry watches Linux syscalls from inside the kernel with eBPF. Four
> rules flag privilege escalation, credential theft, process injection and
> reverse shells, each tagged with its MITRE ATT&CK technique. The part I want
> you to watch is the panel in the middle: those four alerts come from four
> different processes and four different rules, and on their own each one looks
> like noise. The correlator walks the process tree, rolls every alert up to its
> ATT&CK *tactic*, and when one process tree spans three distinct attacker goals
> it raises a single CRITICAL incident with the whole story in order. That is the
> difference between four tickets and one intrusion."

---

## Full demo script

Five acts, about 12 minutes. Each act has the command, what to say, and what to
point at.

### Act 1 — The problem (90 seconds, no commands)

Say this before touching the keyboard:

> "There are two ordinary ways to watch what a process does on Linux, and both
> are bad. `ptrace` stops the target on every syscall and any program can detect
> it. `auditd` is a firehose with a rigid rule language. eBPF lets you run a
> small verified program *inside the kernel*, at the syscall boundary — no
> context switch per event, and the traced process cannot opt out."

> "But collecting syscalls is the easy half. A reverse shell is `socket`,
> `connect`, `dup2`, `execve` — four completely ordinary syscalls. Every HTTP
> client makes the first two. Every shell redirection makes the third. The
> attack is not in any one syscall; it is in the *order*, inside one process,
> inside two seconds. That is what this project is about."

### Act 2 — What is armed (60 seconds)

```bash
./bin/krnlsentry --list-rules
```

> "Five detections. Four of them judge one process at one moment:
> privilege-escalation, sensitive-file-access, process-injection,
> reverse-shell. Each maps to specific MITRE ATT&CK techniques — note the
> sub-techniques: `T1003.008` says '/etc/shadow was read', not just 'credential
> dumping somewhere'. The fifth, `attack-chain`, is the correlator, and it works
> at the level of ATT&CK *tactics* instead."

*If `./bin/krnlsentry` does not exist (you are on macOS and have not built in
the container), use `go run ./cmd/krnlsentry --list-rules` instead — identical
output.*

### Act 3 — The demo (4 minutes) ⭐

```bash
make demo
```

This replays a recorded intrusion — an SSH login whose children read AWS
credentials, `ptrace` the shell, call `setuid(0)` and dial out — **at its
original speed**, on the live dashboard. It takes about 17 seconds at the
default `SPEED=2`.

While it runs, narrate in this order:

1. **Point at the header first** (before alerts arrive):

   > "Totals across the top: events seen, alerts raised, duplicates folded,
   > processes tracked — and drops. That last one matters: a monitoring tool
   > that quietly threw events away looks exactly like one that saw nothing
   > suspicious. It stays at zero and turns red if it ever isn't."

2. **As the first MEDIUM appears** (`cat` reading `~/.aws/credentials`):

   > "Credential Access. On its own: a developer reading their own AWS config.
   > Nobody pages anyone for this."

3. **As the HIGH alerts appear** (`ptrace`, then `setuid(0)`):

   > "Now a `ptrace` attach, and a `setuid(0)` from a non-root process. Still
   > individually explicable — debuggers attach, and that setuid *failed* with
   > EPERM. We trace syscall *entry*, so a denied attempt alerts exactly like a
   > successful one."

4. **As the CRITICAL reverse-shell lands:**

   > "There is the sequence: socket, connect, dup2 onto stdin/stdout/stderr,
   > execve of `/bin/sh`, in one millisecond. And `chain_socket_fd_confirmed` —
   > we captured the fd that `socket()` returned via a `sys_exit` probe and
   > confirmed it is the same fd being duplicated onto the standard streams.
   > That rules out a program that happens to open a socket and separately
   > redirect a file."

5. **Land on the ATTACK CHAIN panel** — this is the finish:

   > "And this is the point of the project. Four alerts, four PIDs, four rules.
   > The correlator rebuilt the process tree from the event stream — including
   > the shell in the middle, which never alerted at all — stopped at the `sshd`
   > session boundary so this is one login's story and not the whole host, and
   > rolled each alert up to its tactic. Five tactics in one tree in eighteen
   > seconds: Credential Access, Defense Evasion, Privilege Escalation,
   > Execution, Command and Control. One CRITICAL incident, with the timeline."

6. **Point at the tactics row:**

   > "Breadth, not volume. A cron job reading `/etc/shadow` fifty times is one
   > tactic however loud — and it is in this capture, deliberately, and it did
   > *not* raise a chain. Three different attacker goals in one tree is the
   > shape of an intrusion and almost never the shape of administration."

### Act 4 — It is real engineering, not a script (3 minutes)

Three things, in this order. These are what a guide or examiner is actually
assessing.

**(a) The alerts are machine-readable, not just pretty.**

```bash
tail -2 "${TMPDIR:-/tmp}/krnlsentry-demo.jsonl" | python3 -m json.tool | head -40
```

> "Every alert is one JSON object on one line. JSONL rather than a JSON array,
> because the file is valid at every instant — a tool killed with SIGKILL leaves
> a complete file minus at most one line, whereas an array without its closing
> bracket is unparseable. Mode 0600, append-only. Every alert carries a
> `storyline` id, so a SIEM can pivot from any one alert to everything related
> with a single equality filter."

**(b) The detection logic knows nothing about eBPF — so it is all testable.**

```bash
make verify
```

> "88 tests, under the race detector, in about three seconds, on a Mac. No
> kernel, no root, no privileged CI runner. That is possible because rules
> operate on a plain `events.Event` struct: the kernel-facing code is in one
> package and the detection logic imports only the standard library. `detect/`
> is at 94.8% statement coverage."

**(c) The same path reproduces and retro-hunts.**

```bash
./bin/krnlsentry --replay testdata/captures/intrusion.jsonl --pid 4100 --output /tmp/scoped.jsonl
grep -c backup.sh /tmp/scoped.jsonl || echo "cron job correctly excluded"
```

> "`--verbose` records every observed syscall losslessly; `--replay` feeds it
> back through the identical filter, engine and sinks. So a rule written today
> can be run over last week's capture, a reported false positive can be
> reproduced from the reporter's capture instead of their description, and
> `--pid` scoping is testable — here the out-of-tree cron job is correctly
> excluded. There is a golden capture in `testdata/` with a unit test that pins
> exactly which alerts, folds and chains it must produce."

### Act 5 — Limits, honestly (90 seconds)

End here, not on a triumphant note. It is the strongest part of the submission.

> "The README has a Limitations section, written on purpose, because a detection
> whose limits you cannot articulate is one you cannot rely on. The three I would
> raise myself:
>
> 1. **The debugger allowlist is `comm`-based and spoofable.** Anything that
>    copies itself to `/tmp/gdb` walks past the ptrace rule. That allowlist buys
>    usability, not security — the real fix is verifying the binary via
>    `/proc/<pid>/exe` and a signature or IMA measurement.
> 2. **Path matching is on the unresolved string.** `openat("/etc/shadow")` is
>    caught; a symlink, a bind mount, or reading the block device is not.
>    Closing that properly means hooking at the LSM layer where the resolved
>    inode is available.
> 3. **No eBPF-side filtering.** Every matching syscall produces a 544-byte
>    event even when `--pid` will discard it immediately. Moving the PID filter
>    into a BPF map consulted inside each probe is the single highest-value
>    improvement available, and it is roadmap item 1."

---

## What to point at on the dashboard

```
╭─ KrnlSentry · REPLAY · system-wide ─────────────────── 00:00:12 ╮
│  events 38  alerts 7  folded 11  tracked 8  drops 0             │   ← (1)
╰─────────────────────────────────────────────────────────────────╯
  SEVERITY ─────────────────  RULES ────────────────────────────       ← (2)
  ATT&CK TACTICS ───────────────────────────────────────────────       ← (3)
  TOP PROCESSES ────────────────────────────────────────────────       ← (4)
  ATTACK CHAIN   open storylines 2   chains raised 2 ───────────       ← (5) ⭐
  RECENT ALERTS   7 total ──────────────────────────────────────       ← (6)
```

| # | Panel | The sentence to say about it |
| - | ----- | ---------------------------- |
| 1 | Totals | "Drops stay at zero and go red if they aren't — silent data loss is the failure mode that looks like success." |
| 2 | Severity + rules | "Zero rows are kept deliberately: `reverse-shell 0` says the rule is armed and quiet. A missing row cannot distinguish that from a rule that is not running." |
| 3 | Tactics | "Tactic breadth is what the correlator decides on — three distinct goals in one tree, not fifty repeats of one." |
| 4 | Top processes | "The triage shortlist. Keyed by PID, not by name, because two `bash` processes are two findings." |
| 5 | **Attack chain** | **The payload. Four rules and four PIDs put back into one ordered story, with the tactic each step served.** |
| 6 | Recent alerts | "Newest first — in a fixed panel the eye lands at the top, unlike a scrolling stream." |

Two details worth volunteering if nobody asks:

- **`--min-severity` filters this feed only, never the totals.** It quietens
  what competes for attention; it must not let you unsee the host.
- **The last frame is left on screen at Ctrl+C**, above the shutdown summary, so
  the run's numbers survive the tool exiting.

---

## The live kernel demo (optional)

Only attempt this if you have a throwaway Linux VM or container ready **and**
you have rehearsed it. It is strictly a bonus; the replay demo already shows
every detection.

```bash
# In a throwaway VM/container, as root:
make build
./bin/krnlsentry --dashboard &
sudo ./test/run-all.sh          # or one scenario at a time
```

On macOS, [Colima](https://github.com/abiosoft/colima) is a better host than
Docker Desktop: its Lima VM runs a stock Ubuntu kernel with
`CONFIG_DEBUG_INFO_BTF=y`, so the agent can actually *run* rather than only
compile.

```bash
colima start --cpu 4 --memory 6
make docker-build
make docker-run
```

> ⚠ The scenario scripts generate genuine security alerts. Throwaway VM or
> container only — never a shared or lab-managed host.

**If the kernel lacks BTF** (`ls /sys/kernel/btf/vmlinux` is missing), say so
plainly and fall back to the replay demo: that is precisely why the replay path
exists, and the agent compiles on macOS and Windows for the same reason.

---

## Likely questions, with answers

**"Why eBPF rather than `auditd` or `ptrace`?"**
`ptrace` halts the target and is trivially detected; `auditd` is a firehose with
a rigid rule language. eBPF filters inside the kernel at the syscall boundary,
with no context switch per event and no opt-out for the traced process.

**"Why libbpf + CO-RE rather than BCC?"**
BCC compiles its kernel programs at runtime, so every target machine needs
clang, LLVM and matching kernel headers. CO-RE compiles once, embeds BTF
relocations, and libbpf patches struct offsets against the running kernel at
load time. The result is a single static Go binary that runs on any 5.8+ kernel
with BTF, with nothing to install on the target.

**"Why a ring buffer and not a perf buffer?"**
`BPF_MAP_TYPE_RINGBUF` delivers events in **global order** across CPUs. A
per-CPU perf buffer does not — and the reverse-shell rule is a *sequence*
detector, so out-of-order delivery would make it silently wrong rather than
merely untidy. The reserve/commit API also lets the kernel fill the event in
place, which matters because a 544-byte event does not fit on BPF's 512-byte
stack.

**"Why tracepoints and not kprobes?"**
Syscall tracepoints are a stable kernel ABI. kprobes on `sys_*` symbols break
across kernel versions and differ by architecture (`__x64_sys_openat` vs
`__arm64_sys_openat`).

**"Why is there no policy in the kernel program?"**
Everything in the BPF program runs in the syscall hot path with the calling
process blocked, under a verifier that forbids unbounded loops. String matching
and rule evaluation fit that environment badly. Keeping policy in Go makes a new
rule a function with a unit test rather than a kernel program re-argued with the
verifier. The cost — every matching syscall produces an event whether a rule
cares or not — is stated in the README.

**"How do you know it works?"**
Three layers. 88 unit tests over rule logic, decoding, the tracker, the
correlator and the renderer — no kernel needed. A golden capture replayed by
`TestReplayGoldenCapture`, which pins exactly which alerts, folds and chains it
must produce. And `test/run-all.sh`, which runs four live scenarios against a
real kernel and exits non-zero if any rule fails to fire.

**"What stops it alerting on itself?"**
The BPF program filters the agent's own PID in kernel space, and the engine
checks it again in user space — so the guarantee does not depend on one filter
still being correct. Without it, writing an alert is a syscall that produces an
event that writes an alert.

**"Is `setuid(0)` failing a false positive?"**
No — it is the design. We trace syscall *entry*, so a denied attempt is reported
exactly like a successful one. A failed privilege-escalation attempt is a
security event; waiting for success would mean only detecting attacks that
worked.

**"Won't this be noisy on a real host?"**
Three mechanisms. Deduplication folds identical findings into one per window
(the resurfaced alert carries `suppressed: N`). The correlator escalates on
tactic *breadth*, so volume alone cannot raise a chain. And `--min-severity`,
`--pid`, `--rules`, `--ignore-loopback` and `--ignore-self-proc` narrow scope.
In the bundled capture, 11 alerts fold into the 7 shown.

**"What is the performance cost?"**
Not measured under load, and I would not claim a number I have not measured.
What I can say is where the cost is: every matching syscall produces a 544-byte
event regardless of whether a rule cares, because collection is deliberately
policy-free. Moving the PID filter into a BPF map is roadmap item 1 for exactly
that reason.

**"Could an attacker evade it?"**
Yes, and the README names how: rename your binary to `gdb`, reach `/etc/shadow`
through a symlink or the block device, issue a raw `open()` instead of
`openat()`, or exploit the TOCTOU window on the setuid `stat`. Each has a
documented fix — binary identity verification, LSM hooks, more probes.

**"What would you do next?"**
In order: eBPF-side PID and cgroup filtering (the performance win), container
and namespace awareness (the biggest coverage gap — right now an alert can carry
a host-namespace PID beside a container-namespace `target_pid`), then binary
identity verification to replace the `comm` allowlist.

---

## If something breaks

| Symptom | Cause | Do this |
| ------- | ----- | ------- |
| Dashboard looks garbled or double-drawn | Terminal too small, so the frame scrolls | Enlarge the window (≥ 100×30) and rerun. The frame adapts, but below 24 rows it stops shedding panels rather than hiding the totals. |
| `--dashboard needs a terminal` warning | stdout is piped or redirected | Do not pipe it. If you must (recording), add `--color` to force it. |
| Colours are absent | `NO_COLOR` is set, or not a TTY | `unset NO_COLOR`, or pass `--color`. |
| Everything appears at once | `--replay-speed` not applied | Use `make demo` (which passes it), or `--replay-speed 2` explicitly. |
| Demo runs too long / too short | Pacing | `make demo SPEED=4` (faster) or `SPEED=1` (real time, 34 s). |
| `make demo` recompiles slowly on stage | Cold build cache | Run `go build ./...` beforehand. |
| `make build` fails: `clang not found` | eBPF needs clang with a BPF target; macOS lacks it | You do not need it for the demo. Use `go run ./cmd/krnlsentry` or `make demo`. For the real build: `make docker-make TARGET=all`. |
| Live run fails to load BPF | Kernel without BTF, or not root | `ls -l /sys/kernel/btf/vmlinux`; run with root or `CAP_BPF`+`CAP_PERFMON`. Fall back to the replay demo. |
| Live run: tracepoint attach fails in a container | `tracefs` not mounted | `mount -t tracefs tracefs /sys/kernel/tracing`, or use `--privileged`. |
| Ctrl+C left the cursor hidden | Only possible on a hard kill (SIGKILL) | `reset` or `tput cnorm`. A normal Ctrl+C restores it — that path is tested. |
| Alert log looks empty | Buffered until flush, or wrong path | The path is printed in the dashboard footer and the banner; the log is flushed and `fsync`ed on exit. |

**The universal fallback.** If anything about the live environment fails:

```bash
make demo SPEED=4
```

It needs nothing but Go and the repository.

---

## One-page cheat sheet

Print this, or keep it in a second terminal tab.

```bash
# PRE-FLIGHT (night before, and again 10 min before)
make verify                       # 88 tests + asserted demo replay

# WARM UP (so nothing compiles on stage)
go build ./... && make demo SPEED=50 && clear

# ── THE DEMO ───────────────────────────────────────────────────
./bin/krnlsentry --list-rules     # Act 2: what is armed
make demo                         # Act 3: ⭐ paced intrusion + dashboard
tail -2 "${TMPDIR:-/tmp}/krnlsentry-demo.jsonl" | python3 -m json.tool
make verify                       # Act 4: the tests
# Act 5: talk through the Limitations section of the README

# VARIATIONS, if asked
make demo SPEED=1                 # real time (34 s)
make demo SPEED=8                 # hurry
./bin/krnlsentry --replay testdata/captures/intrusion.jsonl \
  --pid 4100 --output /tmp/scoped.jsonl     # scope filtering
./bin/krnlsentry --replay testdata/captures/intrusion.jsonl \
  --no-storyline --output /tmp/nochain.jsonl  # same alerts, no correlation
make demo-live                    # Linux + root only
```

**The three sentences that must land:**

1. eBPF filters inside the kernel at the syscall boundary — no context switch
   per event, and the traced process cannot opt out.
2. A reverse shell is four ordinary syscalls; the detection is entirely about
   their *order* within one process, and we confirm the socket fd is the one
   duplicated onto the standard streams.
3. Four alerts from four processes and four rules become **one** incident,
   because the correlator rebuilds the process tree and escalates on ATT&CK
   tactic *breadth* rather than alert volume.
