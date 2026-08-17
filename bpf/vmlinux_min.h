/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * vmlinux_min.h — a hand-written, minimal stand-in for the generated `vmlinux.h`.
 *
 * WHY THIS FILE EXISTS
 * ────────────────────
 * The usual libbpf/CO-RE workflow is:
 *
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * which emits every type the running kernel knows about — a ~3.5 MB header.
 * We deliberately do NOT do that, for two reasons:
 *
 *   1. Build portability. Generating vmlinux.h requires a kernel with
 *      CONFIG_DEBUG_INFO_BTF=y *at build time*. On a Mac running Docker
 *      Desktop, the LinuxKit VM's BTF may be missing, which would make the
 *      project unbuildable on the primary dev environment. A checked-in
 *      header makes `make` work anywhere clang runs.
 *
 *   2. Readability. This is a learning project. A 3.5 MB generated blob tells
 *      you nothing; forty lines of the exact structs we touch tells you
 *      everything.
 *
 * IS THIS STILL CO-RE?
 * ────────────────────
 * Yes. `__attribute__((preserve_access_index))` is the whole trick. It tells
 * clang to emit a BTF *relocation* for every field access inside these structs
 * rather than a hard-coded byte offset. At load time libbpf reads the running
 * kernel's own BTF, finds the field *by name*, and patches the real offset into
 * the instruction stream. So the field offsets written below are irrelevant —
 * we only have to get the field *names* and *types* right, and we may declare a
 * subset of the fields in any order. That is what makes one binary work across
 * kernel versions that shuffle struct layouts.
 *
 * The tracepoint context structs (trace_event_raw_sys_enter/exit) are a
 * different case: the syscall tracepoint layout is a stable kernel ABI, so
 * those offsets genuinely are fixed. We still mark them preserve_access_index
 * for uniformity and future-proofing.
 */

#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

/* ── Fixed-width integer types ───────────────────────────────────────────────
 * BPF programs cannot include libc or kernel UAPI headers, so the real
 * vmlinux.h defines these itself. We do the same.
 */
typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s64 s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __le16;
typedef __u32 __le32;
/* Used only in the prototypes of checksum helpers we never call, but
 * bpf_helper_defs.h declares them unconditionally. */
typedef __u32 __wsum;

typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef _Bool bool;
#define true 1
#define false 0

/* ── Opaque forward declarations ─────────────────────────────────────────────
 * libbpf's bpf_helper_defs.h declares helpers whose prototypes mention kernel
 * types we never use (sockets, sk_buffs, cgroups, ...). Without vmlinux.h those
 * names would first appear inside a parameter list, which C scopes to that one
 * prototype and clang warns about under -Wall. Forward-declaring them at file
 * scope silences the noise without pulling in any definitions.
 */
struct bpf_map;
struct bpf_sock;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct bpf_sock_tuple;
struct bpf_tcp_sock;
struct bpf_sk_lookup;
struct bpf_pidns_info;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_spin_lock;
struct bpf_timer;
struct bpf_dynptr;
struct bpf_sysctl;
struct bpf_redir_neigh;
struct bpf_func_info;
struct __sk_buff;
struct sk_buff;
struct sk_msg_md;
struct xdp_md;
struct xdp_buff;
struct sockaddr;
struct socket;
struct sock;
struct tcphdr;
struct iphdr;
struct ipv6hdr;
struct seq_file;
struct path;
struct file;
struct inode;
struct dentry;
struct linux_binprm;
struct cgroup;
struct tcp6_sock;
struct tcp_sock;
struct tcp_timewait_sock;
struct tcp_request_sock;
struct udp6_sock;
struct unix_sock;
struct mptcp_sock;
struct btf_ptr;
struct pt_regs;
struct task_struct;
struct nf_conn;
struct bpf_ct_opts;
struct bpf_iter_meta;
struct bpf_iter__task;
struct bpf_cpumask;
struct mptcp_subflow_context;
struct bpf_key;
struct bpf_list_head;
struct bpf_list_node;
struct bpf_rb_root;
struct bpf_rb_node;
struct bpf_refcount;
struct bpf_iter_num;
struct bpf_iter_bits;
struct bpf_iter_scx_dsq;
struct bpf_iter_css;
struct bpf_iter_css_task;
struct bpf_iter_task;
struct bpf_iter_task_vma;
struct cgroup_subsys_state;
struct css_set;
struct user_pt_regs;
struct xdp_frame;
struct bpf_devmap_val;
struct bpf_cpumap_val;
struct bpf_res_spin_lock;
struct bpf_task_work;

/* ── enum bpf_map_type ───────────────────────────────────────────────────────
 * These are UAPI constants (include/uapi/linux/bpf.h), so unlike kernel struct
 * layouts they are frozen forever — the enum is append-only and a value never
 * changes meaning. That is what makes it safe to hard-code them here rather
 * than relocate them: there is nothing to relocate.
 *
 * Listed in full up to the two we use so the numbering is self-evidently
 * correct rather than a pair of magic numbers. BPF_MAP_TYPE_RINGBUF == 27 is
 * the one that matters; it appeared in kernel 5.8, which is where this
 * project's minimum kernel version comes from.
 */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
};

/* ── task_struct (partial, CO-RE relocated) ──────────────────────────────────
 * We only need three fields:
 *
 *   pid          — the *thread* id (what the kernel calls a pid).
 *   tgid         — the *process* id (what userspace calls a pid).
 *   real_parent  — the parent task, so we can read its tgid as our PPID.
 *
 * Note `real_parent` rather than `parent`: `parent` points at whoever is
 * currently ptrace-ing the task when one is attached, which would make our PPID
 * lie precisely during the process-injection scenarios we care about.
 * `real_parent` always reflects the true creator.
 *
 * The real task_struct has ~200 fields at wildly different offsets per kernel.
 * Declaring these three is safe *only* because of preserve_access_index.
 */
struct task_struct {
	int pid;
	int tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
} __attribute__((preserve_access_index));

/* ── Tracepoint contexts ─────────────────────────────────────────────────────
 * Every syscall tracepoint under /sys/kernel/debug/tracing/events/syscalls/
 * shares one of these two layouts. You can confirm it yourself:
 *
 *     cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
 *
 * `ent` is the 8-byte common header every ftrace event carries; `id` is the
 * syscall number; `args[6]` are the raw syscall arguments as they appeared in
 * registers. Crucially, pointer arguments here are *userspace* addresses — they
 * are not dereferenceable from BPF. See the bpf_probe_read_user_str() note in
 * krnlsentry.bpf.c.
 */
struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_MIN_H__ */
