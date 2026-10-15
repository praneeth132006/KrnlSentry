# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Attack storylines** (novel)

- Cross-process correlator that builds process lineage from every event (with
  `/proc` gap-filling), groups alerts into storylines bounded by session
  owners (`sshd`, `systemd`, `containerd-shim`, `cron`, …), rolls each alert up
  to its ATT&CK tactic, and raises a CRITICAL `attack-chain` alert carrying an
  ordered `story` when one process tree spans `--chain-threshold` distinct
  tactics. Re-raised when the story gains a tactic; stories merge when lineage
  reveals they are one.
- `storyline` field on every alert for one-filter SIEM pivoting.
- Flags: `--no-storyline`, `--chain-threshold`, `--chain-window`.

**Live dashboard**

- `--dashboard` renders a full-screen, self-repainting display: severity and
  per-rule bars (including armed-but-quiet rules at zero), ATT&CK tactic
  coverage, the processes with the most alerts, open-storyline and chain counts,
  the latest `attack-chain` as a timeline, and a newest-first alert feed.
- Combined kernel and queue drop count is always on screen, and highlighted the
  moment it is non-zero.
- Off by default and refuses a non-terminal stdout — falling back to the
  scrolling stream rather than writing escape codes into a redirect. `--color`
  forces it for recordings.
- `--min-severity` filters the alert feed only; totals always describe the run.
- The final frame is left on screen at shutdown, above the summary.

**Demo and verification**

- `--replay-speed` paces a replay against the capture's own monotonic clock
  (`1` = real time), so a storyline can be watched assembling itself instead of
  arriving all at once. Idle gaps are capped so a quiet capture cannot look like
  a hung process.
- `make demo` (paced replay on the dashboard), `make demo-live`, and
  `make verify` — compile, `-race` unit tests, and `test/demo-check.sh`.
- `test/demo-check.sh`: asserts the demo path through the real binary — CLI
  flags, per-rule alert counts, the `0600` alert log, storyline and story
  fields, dashboard panels and cursor restoration, the non-terminal fallback,
  pacing equivalence, and `--pid` scope exclusion. No root, no eBPF, any OS.

**Replay**

- `--replay <capture>` evaluates a `--verbose` capture through the live
  pipeline, with no kernel and no root. The capture format (`events.Record`)
  now carries typed fields so replay is lossless.
- The agent builds natively on non-Linux hosts (eBPF loader stubbed), so rules
  can be developed and replayed on macOS.
- Golden capture `testdata/captures/intrusion.jsonl`, its generator
  `internal/gencapture`, and `make replay-demo` / `make capture-fixture`.

**Deduplication**

- `--dedup-window` (default 5s) folds identical alerts; the next emission
  carries a `suppressed` count. Closes roadmap item 6.

**Core agent**

**Kernel side**

- eBPF programs on 15 syscall tracepoints — `execve`, `execveat`, `openat`,
  `setuid`, `setgid`, `setresuid`, `setresgid`, `capset`, `ptrace`, `socket`
  (enter + exit), `connect` (enter + exit), `dup2`, `dup3` — built with
  libbpf + CO-RE, no BCC and no runtime compilation.
- 256 KiB `BPF_MAP_TYPE_RINGBUF` for event transport, chosen over a per-CPU perf
  buffer because the reverse-shell rule depends on global event ordering.
- Per-CPU statistics map counting submitted and dropped events, so the agent can
  report when its own coverage was incomplete instead of under-reporting
  silently.
- Self-PID filter in kernel space, preventing a log→syscall→log feedback loop.
- `bpf/vmlinux_min.h`: a hand-written minimal CO-RE header, so building requires
  no BTF on the build host.

**Detection**

- `privilege-escalation` (T1548, T1548.001) — `setuid`/`setresuid`/`setgid`/
  `setresgid` to root and `capset` from non-root processes, plus `execve` of
  setuid/setgid binaries by non-root users.
- `sensitive-file-access` (T1003.007, T1003.008, T1552, T1552.001, T1552.004) —
  `/etc/shadow`, `/etc/sudoers`, SSH and GnuPG private keys, AWS/Docker/kube
  credentials, and `/proc/<pid>/mem` and `maps`.
- `process-injection` (T1055.008) — `ptrace` with `ATTACH`, `SEIZE`, the `POKE*`
  family, and both `SETREGS` and the arm64 `SETREGSET` spelling.
- `reverse-shell` (T1059) — the `socket` → `connect` → `dup2`/`dup3` →
  `execve` sequence within one process, with the socket's file descriptor
  confirmed against the descriptor duplicated onto the standard streams.
- Bounded per-process state tracker: capped depth, TTL eviction and a hard
  process-count ceiling, swept on the event path rather than from a ticker.

**Agent and output**

- JSONL alert log (append-only, `0600`, unbuffered, `fsync` on shutdown) and a
  colour-coded console stream that respects `NO_COLOR` and terminal detection.
- CLI: `--pid`, `--output`, `--rules`, `--verbose`, plus `--min-severity`,
  `--window`, `--ignore-loopback`, `--ignore-self-proc`, `--stats-interval`,
  `--list-rules` and `--version`.
- `--pid` descendant tracking seeded from a `/proc` walk at startup.
- Clean detach of all probes on SIGINT/SIGTERM, and a shutdown summary that
  surfaces any dropped events.

**Documentation**

- `DEMO.md` — a rehearsed presentation script: pre-flight checks, a five-act
  demo with narration, a per-panel guide to the dashboard, prepared answers to
  the questions the design invites, a symptom/cause/fix table, and a one-page
  cheat sheet.
- `REPORT.md` — project report with Mermaid architecture, lifecycle, state and
  correlation diagrams; each design decision stated with its justification;
  code, coverage and detection metrics; limitations; and an ordered roadmap.

**Project**

- Linux dev container (`Dockerfile`, `make docker-*`), which is the only way to
  build on macOS or Windows.
- Unit tests covering argument decoding, all four rules and the tracker, none of
  which need a kernel, root or eBPF. Includes a test that parses `bpf/event.h`
  and fails if the C enum and the Go constants drift apart.
- Four demo scenarios in `test/` plus `run-all.sh`, which doubles as an
  end-to-end smoke test and exits non-zero if any rule fails to fire.
- GitHub Actions CI (build, vet, test, lint, shellcheck, dev-container build)
  and GoReleaser-based release automation.

### Fixed

- Per-rule alert counts in `test/run-all.sh` no longer count an `attack-chain`
  alert again against every rule that contributed to it: the embedded `story`
  carries a `rule` field per step, which the textual count was matching.

### Known limitations

Documented in full in the README. In short: no container or namespace
awareness, no eBPF-side filtering, `comm`-based debugger allowlisting and
session boundaries are spoofable, path matching operates on the unresolved
string, and `capset` is not diffed against the bounding set.

[Unreleased]: https://github.com/praneeth132006/KrnlSentry/commits/main
