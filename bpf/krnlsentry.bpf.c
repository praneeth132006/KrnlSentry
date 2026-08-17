// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * krnlsentry.bpf.c — the kernel-side half of KrnlSentry.
 *
 * WHAT THIS FILE DOES, AND WHAT IT DELIBERATELY DOES NOT
 * ══════════════════════════════════════════════════════
 * This program attaches to a fixed set of syscall tracepoints, copies a small
 * fixed-size record out of each one, and pushes it into a ring buffer. That is
 * all it does. There is no matching, no allowlisting, no path globbing and no
 * policy of any kind in here.
 *
 * That is a design decision, not an omission:
 *
 *   • Everything in this file runs in the syscall hot path, with the calling
 *     process blocked, under a verifier that forbids unbounded loops. String
 *     matching and rule evaluation are exactly the workloads that fit worst.
 *
 *   • The verifier makes this code expensive to change. Keeping policy out of
 *     it means a new detection rule is a pure Go function with a unit test,
 *     not a kernel program that has to be re-argued with the verifier.
 *
 *   • Detection logic that cannot be unit-tested is detection logic nobody
 *     trusts. The Go side can be tested with a struct literal; this side needs
 *     root and a live kernel.
 *
 * The cost is honest and worth stating: every matching syscall on the system
 * produces a 544-byte event, whether or not any rule will care. See
 * "Limitations & Future Work" in the README.
 *
 * TRACEPOINTS RATHER THAN KPROBES
 * ═══════════════════════════════
 * Syscall tracepoints are a stable kernel ABI. kprobes on sys_* symbols are
 * not — they break across kernel versions, differ between architectures, and
 * on modern kernels the real handlers sit behind arch-specific wrappers
 * (__x64_sys_openat, __arm64_sys_openat) whose argument passing differs. Since
 * every event we need is available at the tracepoint, there is no reason to
 * take on that fragility.
 *
 * THE USER-POINTER TRAP
 * ═════════════════════
 * The single most common bug in code like this: the pointer arguments in
 * `ctx->args[]` are *user-space virtual addresses belonging to the traced
 * process*. They are not kernel addresses, and BPF cannot dereference them
 * directly — not with `*p`, and not with bpf_probe_read_kernel(). Doing so
 * either fails verification or, worse, silently reads garbage.
 *
 * They must be copied with the *user* variants:
 *
 *     bpf_probe_read_user()      — fixed-size copy
 *     bpf_probe_read_user_str()  — NUL-terminated copy, returns bytes written
 *
 * These can fail legitimately, and do: the page may be swapped out, or the
 * address may be bogus because we are watching a process being fuzzed. Every
 * call site below checks the return value. A failed read leaves the field as
 * the zero we memset it to, which user space renders as an empty string — an
 * event with a missing path is still worth reporting, so we never drop it.
 */

#include "vmlinux_min.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

/* Address families. Defined locally rather than pulled from UAPI headers,
 * which BPF programs cannot include. */
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

/* ════════════════════════════════════════════════════════════════════════════
 * Maps
 * ════════════════════════════════════════════════════════════════════════════
 */

/*
 * The event channel. BPF_MAP_TYPE_RINGBUF (kernel 5.8+) replaces the older
 * perf event array, and is the reason this project requires 5.8. It matters
 * here for two specific reasons:
 *
 *   1. One shared buffer instead of one per CPU. With a perf buffer, events
 *      arrive per-CPU and user space has to re-order them; the reverse-shell
 *      rule below is a *sequence* detector, so out-of-order delivery would be
 *      an actual correctness problem, not just untidiness. The ring buffer
 *      preserves global ordering.
 *
 *   2. Reserve/commit instead of copy. bpf_ringbuf_reserve() hands us the
 *      final destination memory, so we fill the event once rather than
 *      building it on the stack and copying. The 512-byte BPF stack limit
 *      makes that more than an optimisation — a 544-byte event physically
 *      does not fit on the stack.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/*
 * Runtime configuration, written once by the agent at startup.
 *
 * This holds exactly one thing: our own TGID, so we can drop our own syscalls.
 * That is not an optimisation, it is a correctness requirement — the agent
 * writes alerts to a file, so without this filter every openat() we perform
 * generates an event, which we then process and log, which generates another
 * openat(). A feedback loop that saturates a CPU the first time something
 * matches a rule.
 *
 * Note what is *not* here: the --pid filter. That is applied in user space, so
 * that the collection layer stays policy-free and swappable (see the module
 * comment). It is the honest trade-off recorded in the README.
 */
struct config {
	__u32 self_tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} config_map SEC(".maps");

/*
 * Force `struct event` into the object's BTF.
 *
 * This looks like dead code and is load-bearing. Clang only emits BTF for types
 * that are actually *reachable* from a program's signature or a map definition.
 * `struct event` is neither: it only ever appears behind a pointer inside
 * always-inlined helpers, so the optimiser prunes its type information entirely
 * and the compiled object contains no description of it.
 *
 * That breaks the one guarantee this project relies on — bpf2go generates the
 * Go mirror of this struct *from the BTF*, so with the type pruned it fails with
 * "looking up type event: not found", and had we instead hand-written the Go
 * struct we would have silently lost the compile-time layout check.
 *
 * Declaring an unused pointer variable of the type makes it reachable. This is
 * the standard libbpf idiom; every bpf2go project has some version of this line.
 */
const struct event *unused_event_type_anchor __attribute__((unused));

/* Minimal sockaddr shapes for parsing connect()'s second argument out of user
 * memory. We define our own rather than using CO-RE on the kernel's sockaddr,
 * because this memory belongs to the traced process and follows the stable
 * userspace ABI, not the kernel's internal layout. */
struct sockaddr_hdr {
	__u16 sa_family;
};

struct sockaddr_in_user {
	__u16 sin_family;
	__u16 sin_port; /* network byte order */
	__u32 sin_addr; /* network byte order */
};

struct sockaddr_in6_user {
	__u16 sin6_family;
	__u16 sin6_port;
	__u32 sin6_flowinfo;
	__u8 sin6_addr[16];
};

/* ════════════════════════════════════════════════════════════════════════════
 * Helpers
 * ════════════════════════════════════════════════════════════════════════════
 */

/*
 * Zero every field the caller might not write.
 *
 * bpf_ringbuf_reserve() returns *uninitialised* kernel memory. The verifier
 * permits submitting it partially written, which makes this easy to forget —
 * and forgetting it means whatever the kernel last used those pages for gets
 * handed to user space and written to a log file. This is a real, if
 * unglamorous, information leak, so we clear the variable-length regions and
 * the explicit padding unconditionally.
 *
 * The fixed scalar fields are all assigned by fill_common() or the caller, so
 * they do not need clearing here.
 */
static __always_inline void zero_variable_fields(struct event *e)
{
	__builtin_memset(e->path, 0, sizeof(e->path));
	__builtin_memset(e->argv, 0, sizeof(e->argv));
	__builtin_memset(e->_pad, 0, sizeof(e->_pad));
	e->argc = 0;
	e->ret = 0;
	e->arg0 = 0;
	e->arg1 = 0;
	e->arg2 = 0;
	e->daddr = 0;
	e->dport = 0;
	e->family = 0;
	e->flags = 0;
}

/*
 * Return true if we should ignore this task entirely.
 *
 * Only self-filtering, for the feedback-loop reason described on config_map.
 * A missing config entry (agent still starting up) fails open — we would
 * rather emit a few of our own startup syscalls than silently drop the first
 * events after attach.
 */
static __always_inline bool should_skip(__u32 tgid)
{
	__u32 key = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &key);

	if (!cfg)
		return false;

	return cfg->self_tgid != 0 && cfg->self_tgid == tgid;
}

/*
 * Populate the identity fields shared by every event.
 *
 * On UID: bpf_get_current_uid_gid() returns the *real* uid, and we sample it on
 * syscall entry. Both details matter for the privilege-escalation rules. If we
 * read it on exit, a successful setuid(0) would report uid=0 and look like root
 * legitimately calling setuid — the escalation would erase its own evidence.
 * Reading on entry records who the process was *before* the call.
 */
static __always_inline void fill_common(struct event *e, __u32 syscall_id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->timestamp = bpf_ktime_get_ns();
	e->pid = (__u32)pid_tgid;         /* low 32 bits: thread id */
	e->tgid = (__u32)(pid_tgid >> 32); /* high 32 bits: process id */
	e->uid = (__u32)uid_gid;
	e->gid = (__u32)(uid_gid >> 32);
	e->syscall_id = syscall_id;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/*
	 * PPID via CO-RE. bpf_get_current_task() hands back a kernel pointer,
	 * so BPF_CORE_READ (which expands to bpf_probe_read_kernel with
	 * relocated offsets) is the correct reader here — the user variants
	 * would be wrong. real_parent rather than parent: see vmlinux_min.h.
	 *
	 * BPF_CORE_READ swallows read failures and yields 0, which is the
	 * behaviour we want. A task whose parent is being torn down
	 * concurrently should still produce an event; ppid=0 reads as "unknown"
	 * downstream.
	 */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

/*
 * Reserve and pre-fill an event, or return NULL if we should not emit one.
 *
 * NULL happens in two cases, and the difference matters operationally:
 *   - should_skip() said so (our own process) — expected, not an error.
 *   - the ring buffer is full — user space is not draining fast enough and we
 *     are dropping events. There is no way to signal that from here without a
 *     counter map; the userspace reader detects it instead via the ring
 *     buffer's own dropped-sample accounting.
 */
static __always_inline struct event *event_begin(__u32 syscall_id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	if (should_skip(tgid))
		return NULL;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return NULL;

	zero_variable_fields(e);
	fill_common(e, syscall_id);

	return e;
}

/*
 * Copy a NUL-terminated string out of the traced process's address space.
 *
 * Failure is non-fatal by design: the field stays zeroed and the event is still
 * emitted. A page-fault on a path we wanted to read is not a reason to lose the
 * fact that openat() happened.
 */
static __always_inline void read_user_path(struct event *e, const void *uptr)
{
	if (!uptr)
		return;

	long n = bpf_probe_read_user_str(e->path, sizeof(e->path), uptr);

	if (n < 0)
		e->path[0] = '\0';
}

/*
 * Copy up to MAX_ARGV entries of execve's argv.
 *
 * Two levels of user memory here, and both need bpf_probe_read_user():
 * `argv` is a user pointer to an array of user pointers, each of which points
 * at a user string. Reading argv[i] directly would dereference user memory
 * from the kernel — the exact mistake this file's header warns about.
 *
 * #pragma unroll rather than a real loop: this must compile on kernel 5.8,
 * which predates bpf_loop(), and bounded back-edges only became verifiable
 * later. Unrolling with a compile-time constant bound is the portable form.
 * MAX_ARGV is small (3) precisely so that unrolling stays cheap — this runs
 * inline in every exec on the system.
 *
 * Stopping at the first failed or NULL entry is correct: argv is NULL-
 * terminated, so a NULL means we reached the end of the real argument list.
 */
static __always_inline void read_user_argv(struct event *e, const void *argv_ptr)
{
	if (!argv_ptr)
		return;

	const char *const *argv = argv_ptr;

#pragma unroll
	for (int i = 0; i < MAX_ARGV; i++) {
		const char *arg = NULL;

		if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0)
			break;

		if (!arg)
			break;

		if (bpf_probe_read_user_str(e->argv[i], ARG_LEN, arg) < 0)
			break;

		e->argc = i + 1;
	}
}

/*
 * Parse connect()'s sockaddr out of user memory.
 *
 * We read the 2-byte family first and only then read the family-specific
 * shape. Reading a fixed 16 bytes unconditionally would over-read for AF_UNIX
 * sockets with short paths and fail the copy, losing the family information
 * too.
 *
 * IPv6 records family and port but not the address — there is no room for a
 * 16-byte address in the fixed event and IPv4 covers the reverse-shell demo
 * cases. Recorded as a limitation in the README rather than silently ignored.
 */
static __always_inline void read_sockaddr(struct event *e, const void *uaddr)
{
	if (!uaddr)
		return;

	struct sockaddr_hdr hdr = {};

	if (bpf_probe_read_user(&hdr, sizeof(hdr), uaddr) != 0)
		return;

	e->family = hdr.sa_family;

	if (hdr.sa_family == AF_INET) {
		struct sockaddr_in_user sin = {};

		if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) != 0)
			return;

		e->daddr = sin.sin_addr;
		e->dport = sin.sin_port;
	} else if (hdr.sa_family == AF_INET6) {
		struct sockaddr_in6_user sin6 = {};

		if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) != 0)
			return;

		e->dport = sin6.sin6_port;
	}
}

/* ════════════════════════════════════════════════════════════════════════════
 * Probes — process execution
 * ════════════════════════════════════════════════════════════════════════════
 */

/*
 * execve(const char *filename, char *const argv[], char *const envp[])
 *
 * Feeds two rules: the SUID-binary check (which stats `path` in user space —
 * deliberately not here, since a filesystem stat from a BPF program is neither
 * possible nor desirable) and the terminal step of the reverse-shell chain.
 *
 * envp is intentionally not read. It routinely contains credentials, and a
 * security tool that copies secrets into a log file has created a worse
 * problem than the one it detects.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_EXECVE);

	if (!e)
		return 0;

	read_user_path(e, (const void *)ctx->args[0]);
	read_user_argv(e, (const void *)ctx->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * execveat(int dfd, const char *filename, char *const argv[],
 *          char *const envp[], int flags)
 *
 * The same event with the arguments shifted by one. Worth covering separately
 * rather than assuming execve is enough: execveat with AT_EMPTY_PATH executing
 * an anonymous memfd is the standard fileless-execution technique, and a
 * monitor that only watches execve misses it entirely. We record dfd and flags
 * so user space can recognise that shape.
 */
SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_EXECVEAT);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* dfd */
	e->arg1 = (__s64)ctx->args[4]; /* flags */

	read_user_path(e, (const void *)ctx->args[1]);
	read_user_argv(e, (const void *)ctx->args[2]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Probes — file access
 * ════════════════════════════════════════════════════════════════════════════
 */

/*
 * openat(int dfd, const char *filename, int flags, umode_t mode)
 *
 * The highest-volume probe by a wide margin — practically every process opens
 * files constantly — which is exactly why the sensitive-path matching lives in
 * user space where it can be a glob list rather than verifier-legal string
 * comparison.
 *
 * Note that `path` is the path *as the caller wrote it*: possibly relative,
 * possibly containing symlinks or `..`. We are recording the caller's intent,
 * not the kernel's resolved inode. That is a genuine evasion gap (a symlink to
 * /etc/shadow will not match a /etc/shadow rule) and is documented as such.
 * Closing it properly means hooking at the LSM or VFS layer instead.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_OPENAT);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* dfd */
	e->arg1 = (__s64)ctx->args[2]; /* flags */
	e->arg2 = (__s64)ctx->args[3]; /* mode */

	read_user_path(e, (const void *)ctx->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Probes — privilege change
 * ════════════════════════════════════════════════════════════════════════════
 */

/*
 * setuid(uid_t uid) / setgid(gid_t gid)
 *
 * Emitted unconditionally, including from root. The "was the caller non-root?"
 * test belongs to the detection rule, not here: a collector that only reports
 * suspicious calls cannot be used to answer questions its author did not
 * anticipate, and --verbose mode exists precisely so the full stream is
 * available.
 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_SETUID);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* target uid */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_SETGID);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* target gid */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * setresuid(uid_t ruid, uid_t euid, uid_t suid)
 *
 * The one that actually matters in practice. setuid() is the textbook call,
 * but real exploit payloads overwhelmingly use setresuid(0,0,0) because it
 * sets all three ids in a single call and leaves no saved-uid to drop back to.
 * A monitor watching only setuid() misses most of what it is looking for.
 *
 * Any of the three arguments may be (uid_t)-1 meaning "leave unchanged", which
 * sign-extends to -1 here. The rule in user space must treat -1 as "not
 * requested" rather than as a target id.
 */
SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_SETRESUID);

	if (!e)
		return 0;

	e->arg0 = (__s64)(__s32)ctx->args[0]; /* ruid */
	e->arg1 = (__s64)(__s32)ctx->args[1]; /* euid */
	e->arg2 = (__s64)(__s32)ctx->args[2]; /* suid */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_SETRESGID);

	if (!e)
		return 0;

	e->arg0 = (__s64)(__s32)ctx->args[0]; /* rgid */
	e->arg1 = (__s64)(__s32)ctx->args[1]; /* egid */
	e->arg2 = (__s64)(__s32)ctx->args[2]; /* sgid */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * capset(cap_user_header_t hdrp, const cap_user_data_t datap)
 *
 * Both arguments are user pointers to capability bitmask structs. We record
 * only that the call happened, not its contents.
 *
 * That is the MVP scope from the spec, and the reason is worth being explicit
 * about: deciding whether a capset() *raises* privileges requires diffing the
 * requested set against the process's current bounding set, which means
 * reading task->cred->cap_bset via CO-RE and comparing three 64-bit masks.
 * Entirely doable, and listed as a stretch goal — but a half-implemented
 * version that guesses would produce false alerts on every process that
 * legitimately *drops* capabilities at startup, which is most daemons.
 */
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_CAPSET);

	if (!e)
		return 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Probes — process injection
 * ════════════════════════════════════════════════════════════════════════════
 */

/*
 * ptrace(long request, long pid, unsigned long addr, unsigned long data)
 *
 * `request` is the whole story: PTRACE_ATTACH/SEIZE for gaining control,
 * POKETEXT/POKEDATA for writing into another process's memory, SETREGS for
 * hijacking its execution. The numeric values are decoded in user space.
 *
 * `addr` is captured because for POKETEXT it is the target address being
 * written — useful context in an alert, and meaningless to interpret here.
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_PTRACE);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* request */
	e->arg1 = (__s64)ctx->args[1]; /* target pid */
	e->arg2 = (__s64)ctx->args[2]; /* addr */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Probes — the reverse-shell chain
 * ════════════════════════════════════════════════════════════════════════════
 *
 * socket → connect → dup2×N → execve is the canonical reverse shell: open a
 * socket, dial home, wire the socket onto stdin/stdout/stderr, then exec a
 * shell that now talks over the network. No single one of these syscalls is
 * suspicious on its own — every network client on the machine does the first
 * two — so the detection is entirely about the *sequence*, which is assembled
 * in user space by the per-process tracker.
 */

/*
 * socket(int family, int type, int protocol)
 *
 * Paired with a sys_exit probe below, because entry sees the arguments and
 * exit sees the returned fd. We need both: the fd is what lets us later confirm
 * that the dup2() is duplicating *this socket* rather than an unrelated
 * descriptor, which is the difference between a real detection and noise from
 * any program that happens to open a socket and redirect a file.
 */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_SOCKET);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* family */
	e->arg1 = (__s64)ctx->args[1]; /* type */
	e->arg2 = (__s64)ctx->args[2]; /* protocol */
	e->family = (__u16)ctx->args[0];

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * socket() return — the allocated file descriptor, or a negative errno.
 * Arguments are gone by now; only `ret` is meaningful here.
 */
SEC("tracepoint/syscalls/sys_exit_socket")
int trace_socket_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct event *e = event_begin(KS_SYS_SOCKET);

	if (!e)
		return 0;

	e->flags |= KS_FLAG_SYS_EXIT;
	e->ret = ctx->ret;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * connect(int fd, const struct sockaddr *addr, int addrlen)
 *
 * The destination is read from user memory here rather than reconstructed from
 * kernel socket state, because at syscall entry the kernel has not yet touched
 * the socket — the address only exists in the caller's buffer.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_CONNECT);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* fd */
	e->arg1 = (__s64)ctx->args[2]; /* addrlen */

	read_sockaddr(e, (const void *)ctx->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * connect() return. Distinguishes a completed connection from a failed or
 * in-progress one (-EINPROGRESS on non-blocking sockets), which keeps the
 * chain rule from firing on connections that never established.
 */
SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct event *e = event_begin(KS_SYS_CONNECT);

	if (!e)
		return 0;

	e->flags |= KS_FLAG_SYS_EXIT;
	e->ret = ctx->ret;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * dup2(int oldfd, int newfd)
 *
 * The redirection step. newfd of 0, 1 or 2 means the caller is replacing
 * stdin, stdout or stderr — the signature move of a reverse shell.
 */
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_DUP2);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* oldfd */
	e->arg1 = (__s64)ctx->args[1]; /* newfd */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * dup3(int oldfd, int newfd, int flags)
 *
 * Covered separately and not as an afterthought: glibc's dup2() is implemented
 * on top of dup3() on modern systems, and on arm64 there is no dup2 syscall at
 * all — only dup3. Watching just dup2 would make the reverse-shell rule
 * silently never fire on an ARM machine, which is a failure mode worth
 * avoiding on a project whose primary dev box is an M-series Mac.
 */
SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_dup3(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = event_begin(KS_SYS_DUP3);

	if (!e)
		return 0;

	e->arg0 = (__s64)ctx->args[0]; /* oldfd */
	e->arg1 = (__s64)ctx->args[1]; /* newfd */
	e->arg2 = (__s64)ctx->args[2]; /* flags */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Required by the kernel's BPF loader.
 *
 * This must be GPL-compatible and it is not a formality: bpf_probe_read_user_str
 * — the helper this entire program is built around — is gpl_only. Declaring
 * anything else here makes every probe above fail to load with -EACCES.
 *
 * "Dual BSD/GPL" satisfies the kernel's GPL-compatibility check while leaving
 * this file usable under BSD terms, which is why it is preferred over a bare
 * "GPL" in projects (like this one) whose userspace is permissively licensed.
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
