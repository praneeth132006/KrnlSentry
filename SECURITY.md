# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability.

Report it privately through
[GitHub Security Advisories](https://github.com/praneeth132006/KrnlSentry/security/advisories/new),
or by email to **praneeth132006b@gmail.com**.

Include the kernel version, architecture, and enough detail to reproduce. You
will get an acknowledgement within a week. This is a personal open-source
project, so there is no formal SLA — but reports will be taken seriously and
credited unless you prefer otherwise.

## Scope

KrnlSentry loads eBPF programs into the kernel and runs with root or
`CAP_BPF`/`CAP_PERFMON`. That makes the following particularly interesting:

- **Anything that could crash or hang the kernel.** The BPF verifier is the
  first line of defence here, but a program that passes verification can still
  behave badly.
- **Information disclosure through the ring buffer.** `bpf_ringbuf_reserve()`
  returns uninitialised kernel memory, so any field the probes fail to zero
  leaks kernel memory into a world-readable-ish log. The event struct is
  explicitly zeroed for this reason; a gap in that is a real vulnerability.
- **Anything that lets an unprivileged process influence what the agent writes
  to disk**, including path traversal through a crafted `openat` argument.
- **Privilege escalation via the agent itself** — it runs as root, so a bug
  that lets a traced process control its behaviour is serious.

## Explicitly out of scope

These are **known, documented limitations**, not vulnerabilities. They are
described in detail in the README's
[Limitations](README.md#limitations--future-work) section:

- **Bypassing the `comm`-based debugger allowlist** by renaming a binary. The
  allowlist exists for usability, not security, and the README says so.
- **Evading path matching** with symlinks, bind mounts, relative paths, or raw
  `open()` instead of `openat()`. Matching happens on the unresolved string at
  the syscall boundary.
- **Evading detection generally.** KrnlSentry is a monitoring tool, not an
  enforcement mechanism. It observes and reports; it does not block. A
  sufficiently careful attacker who knows the rule set can avoid tripping it.
- **Dropped events under load.** The ring buffer is finite. Drops are counted
  and reported at shutdown rather than hidden, which is the intended behaviour.

If you think one of these is worse than documented, or that a documented
limitation has a materially cheaper bypass than described, that *is* worth
reporting — the accuracy of the limitations section is itself a security
property.

## Supported versions

The `main` branch is the supported version. This is a learning-focused project
without long-term release branches.

## A note on running this

KrnlSentry is a portfolio and learning project. It is genuinely functional and
tested, but it has not had the adversarial review a production security tool
needs. Do not make it your only detection capability. If you want something
battle-tested in this space, look at
[Falco](https://falco.org/) or [Tetragon](https://tetragon.io/).
