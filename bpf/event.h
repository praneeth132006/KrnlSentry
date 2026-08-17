/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * event.h — the wire format between kernel space and user space.
 *
 * This single struct is the entire contract across the ring buffer. Go's view
 * of it is generated automatically by bpf2go from the BTF embedded in the
 * compiled object, so the two sides cannot drift: if you edit this struct and
 * rebuild, the Go type changes with it and any mismatched field use fails to
 * compile. That is why there is no hand-maintained Go mirror of this struct.
 *
 * LAYOUT DISCIPLINE
 * ─────────────────
 * Fields are ordered largest-alignment-first so the compiler inserts no
 * implicit padding. Implicit padding is not just wasted bytes — uninitialised
 * padding is uninitialised *kernel* memory, and copying it into a ring buffer
 * leaks it to user space. We keep the layout explicit and memset the variable
 * regions we do not fill (see zero_variable_fields() in krnlsentry.bpf.c).
 *
 *   offset  size  field
 *   ------  ----  -----------------
 *        0     8  timestamp
 *        8     4  pid
 *       12     4  tgid
 *       16     4  uid
 *       20     4  gid
 *       24     4  ppid
 *       28     4  syscall_id
 *       32     8  ret
 *       40     8  arg0
 *       48     8  arg1
 *       56     8  arg2
 *       64     4  daddr
 *       68     2  dport
 *       70     2  family
 *       72     1  argc
 *       73     3  _pad          (explicit, so it is visibly zeroed)
 *       76     4  flags
 *       80    16  comm
 *       96   256  path
 *      352   192  argv[3][64]
 *      ----------
 *      544 bytes total, 8-byte aligned.
 */

#ifndef __KRNLSENTRY_EVENT_H__
#define __KRNLSENTRY_EVENT_H__

/* TASK_COMM_LEN in the kernel. bpf_get_current_comm() will never write more. */
#define COMM_LEN 16

/* Truncation limits. Longer values are cut short, never dropped: a truncated
 * path still tells the detection engine which file family was touched. */
#define PATH_LEN 256
#define ARG_LEN 64
#define MAX_ARGV 3

/* Ring buffer size. 256 KiB holds ~480 events; at the syscall rates these
 * probes see, that is several hundred milliseconds of slack for the userspace
 * reader to fall behind before the kernel starts dropping. */
#define RINGBUF_SIZE (256 * 1024)

/*
 * Syscall discriminator.
 *
 * We send a small integer rather than a string: it keeps the event fixed-size,
 * costs nothing to produce in the kernel, and pushes the (purely cosmetic) job
 * of naming things into user space where it belongs. Values are explicit so
 * that reordering this enum can never silently remap old events.
 */
enum ks_syscall {
	KS_SYS_UNKNOWN   = 0,
	KS_SYS_EXECVE    = 1,
	KS_SYS_EXECVEAT  = 2,
	KS_SYS_OPENAT    = 3,
	KS_SYS_SETUID    = 4,
	KS_SYS_SETGID    = 5,
	KS_SYS_SETRESUID = 6,
	KS_SYS_SETRESGID = 7,
	KS_SYS_PTRACE    = 8,
	KS_SYS_SOCKET    = 9,
	KS_SYS_CONNECT   = 10,
	KS_SYS_DUP2      = 11,
	KS_SYS_DUP3      = 12,
	KS_SYS_CAPSET    = 13,
};

/*
 * Event flags.
 *
 * KS_FLAG_SYS_EXIT marks an event produced by a sys_exit probe rather than a
 * sys_enter probe. Only `ret` (and the identity fields) are meaningful on those
 * — the argument registers have already been clobbered by the time the syscall
 * returns, which is exactly why we need two probes to see both the arguments
 * and the result of socket()/connect().
 */
#define KS_FLAG_SYS_EXIT (1U << 0)

/*
 * Statistics counter slots.
 *
 * The ring buffer gives no indication to user space when it drops an event —
 * bpf_ringbuf_reserve() simply returns NULL in the kernel and the reader never
 * learns anything happened. For a security monitor that silence is
 * unacceptable: "no alerts" and "alerts were dropped on the floor" must not
 * look identical. These counters make the difference observable.
 */
enum ks_stat {
	KS_STAT_EVENTS  = 0, /* events successfully submitted */
	KS_STAT_DROPPED = 1, /* ring buffer full; event lost */
	KS_STAT_MAX     = 2,
};

struct event {
	/* Nanoseconds since boot (CLOCK_MONOTONIC). Deliberately *not* wall
	 * clock: bpf_ktime_get_ns() is the cheap, monotonic option, and it
	 * cannot jump backwards mid-capture the way a settimeofday() would.
	 * User space converts it to an absolute timestamp using a boot-time
	 * offset captured once at startup. */
	__u64 timestamp;

	__u32 pid;  /* kernel pid  == thread id */
	__u32 tgid; /* kernel tgid == the "PID" user space talks about */
	__u32 uid;  /* real uid at time of call — the pre-escalation identity */
	__u32 gid;
	__u32 ppid; /* real_parent->tgid */

	__u32 syscall_id; /* enum ks_syscall */

	__s64 ret; /* meaningful only when KS_FLAG_SYS_EXIT is set */

	/* Raw syscall arguments, meaning depends on syscall_id. Kept as generic
	 * slots rather than a union of per-syscall structs: a union would make
	 * the Go side a pile of unsafe casts for no space saving, since the
	 * event is fixed-size regardless. Decoding happens in user space. */
	__s64 arg0;
	__s64 arg1;
	__s64 arg2;

	/* connect() destination, parsed from the user-space sockaddr.
	 * daddr is IPv4 in network byte order; zero for other families. */
	__u32 daddr;
	__u16 dport;  /* network byte order */
	__u16 family; /* AF_INET, AF_INET6, AF_UNIX, ... */

	__u8 argc; /* number of argv slots actually populated (0..MAX_ARGV) */
	__u8 _pad[3];
	__u32 flags; /* KS_FLAG_* */

	char comm[COMM_LEN];

	/* execve/execveat filename, or openat pathname. NUL-terminated. */
	char path[PATH_LEN];

	/* First MAX_ARGV entries of execve's argv. Context only — no detection
	 * rule depends on these — but it turns "bash ran something" into
	 * "bash ran `nc -e /bin/sh`" in the alert, which is the difference
	 * between a usable alert and a triage chore. */
	char argv[MAX_ARGV][ARG_LEN];
};

#endif /* __KRNLSENTRY_EVENT_H__ */
