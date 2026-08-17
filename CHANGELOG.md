# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Known limitations

Documented in full in the README. In short: no container or namespace
awareness, no eBPF-side filtering, `comm`-based debugger allowlisting is
spoofable, path matching operates on the unresolved string, and `capset` is not
diffed against the bounding set.

[Unreleased]: https://github.com/praneeth132006/KrnlSentry/commits/main
