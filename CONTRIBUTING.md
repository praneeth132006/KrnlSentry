# Contributing to KrnlSentry

Thanks for your interest. This document covers how to get a working build, what
the review bar is, and where the sharp edges are.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Getting a build

eBPF is Linux-only. On macOS or Windows the dev container is not a convenience,
it is the only option.

```bash
git clone https://github.com/praneeth132006/KrnlSentry.git
cd KrnlSentry

make docker-build                 # Ubuntu 24.04 + clang + libbpf + Go
make docker-make TARGET=all       # generate, build, test
make docker-shell                 # interactive toolchain shell
```

On Linux with `clang`, `libbpf-dev` and Go 1.25+ installed:

```bash
make all
```

### Actually running it on macOS

[Colima](https://github.com/abiosoft/colima) gives you a stock Ubuntu kernel
with BTF, so live tracing works. Docker Desktop's LinuxKit kernel usually does
not have BTF, which is fine for compiling but prevents loading.

```bash
colima start --cpu 4 --memory 6
make docker-run
```

---

## Where to make a change

**Adding a detection rule is the cheap path, and that is by design.** If your
idea can be expressed as a function of an `events.Event` plus that process's
recent history, you never need to touch the kernel code.

1. Add `detect/yourrule.go` with a `Rule` value and an `eval` function.
2. Add the name constant to `detect/engine.go` and register the rule in
   `allRules`.
3. Add `detect/yourrule_test.go` — table tests, using the helpers in
   `helpers_test.go`. No kernel or root required.
4. Add a row to the detection table in `README.md`.

> Rule names are a public contract: they appear in every alert's `rule` field
> and in `--rules`, so people build filters and dashboards on them. Adding a
> name is free; changing one is a breaking change.

**Adding a syscall probe** means touching `bpf/krnlsentry.bpf.c`:

1. Add the enum value to `bpf/event.h` **at the end** — never renumber, it would
   silently mislabel every event.
2. Add the constant to `events/syscall.go`. `TestSyscallIDsMatchCHeader` parses
   the header and will fail if the two drift.
3. Write the probe. Read user pointers with `bpf_probe_read_user{,_str}` and
   check the return.
4. Register the tracepoint in `ebpfloader/loader.go`.
5. Decode the arguments in `events/event.go`.

**Changing the event struct** (`bpf/event.h`) needs no Go-side change: bpf2go
regenerates the Go type from BTF. Keep fields ordered largest-alignment-first so
no implicit padding appears, and zero anything you do not write —
`bpf_ringbuf_reserve` hands you uninitialised *kernel* memory, and shipping it
to user space is an information leak.

---

## Before opening a pull request

```bash
make docker-make TARGET=all       # generate + build + test
make docker-make TARGET=vet
gofmt -l .                        # must print nothing
```

CI runs the same steps plus `golangci-lint` on Ubuntu.

If you changed anything in `bpf/` or `detect/`, also run the end-to-end
scenarios — unit tests cannot tell you whether a probe actually attaches:

```bash
docker run --rm --privileged -v "$PWD":/src krnlsentry-dev \
  bash -c "make build && ./test/run-all.sh"
```

### Review bar

- **Error handling is not optional.** Every kernel interaction — map lookup,
  ring buffer read, probe attachment — gets an explicit check and a message that
  says what failed and what to do about it. "Production quality" is the point of
  this project, not a nice-to-have.
- **Explain non-obvious decisions in comments.** The existing code says *why*
  rather than *what*, especially where the kernel behaves surprisingly. Match it.
- **Negative tests carry the weight.** A rule with only positive tests is a rule
  nobody can tell is too noisy to leave enabled. Show what does *not* fire.
- **State new limitations in the README.** A detection whose limits are not
  written down is a detection nobody can rely on. If your rule has a bypass, say
  so — that is more valuable than pretending it does not.

### Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat(detect): add rule for LD_PRELOAD injection via execve environment
fix(ebpfloader): detach probes when ring buffer creation fails
docs(readme): document namespace-mixing in ptrace alerts
```

Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`,
`chore`. Scopes: `bpf`, `ebpfloader`, `events`, `detect`, `output`, `cmd`,
`test`, `readme`.

---

## Sharp edges

Things that have already cost someone an afternoon:

**User pointers are not kernel pointers.** Syscall arguments in `ctx->args[]`
are addresses in the *traced process's* address space. Dereferencing them, or
using `bpf_probe_read_kernel`, either fails verification or silently reads
garbage. Use the `_user` variants.

**Clang prunes unused BTF.** A type only referenced through an inlined helper
disappears from the object entirely, and bpf2go then fails with
`looking up type X: not found`. The fix is the
`unused_event_type_anchor` declaration in `krnlsentry.bpf.c`.

**`-O0` does not verify.** The verifier rejects clang's unoptimised output.
`-O2` is required, not preferred.

**`dup2` does not exist on arm64.** Only `dup3`. Anything matching descriptor
redirection must handle both, or it is silently dead on ARM. The same applies to
`PTRACE_SETREGS`, which arm64 replaces with `PTRACE_SETREGSET`.

**`fs.FileMode` is not the Unix mode.** Go carries setuid as bit 1<<23, not as
`0o4000` in the permission bits. `0o4755` is an ordinary file with strange
permissions; you want `0o755 | os.ModeSetuid`.

**Go map iteration is randomised.** Any output built from a map must sort first,
or two identical alerts print differently and look like a bug.

---

## Reporting bugs

Open an issue with the kernel version (`uname -r`), distribution, architecture,
whether `/sys/kernel/btf/vmlinux` exists, and the full error. For a verifier
rejection, include the whole log — the useful part is rarely at the end.

Security vulnerabilities: see [SECURITY.md](SECURITY.md), not a public issue.
