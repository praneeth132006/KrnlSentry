// Package events defines the canonical, transport-neutral representation of a
// observed syscall, plus the decoding that turns raw kernel arguments into
// human- and rule-readable values.
//
// This package is the seam in the architecture. It imports nothing outside the
// standard library — in particular it knows nothing about eBPF, ring buffers,
// or the cilium/ebpf module. Everything downstream of collection (the detection
// engine, the output sinks) depends only on this package.
//
// That constraint is the point. The collection layer can be replaced — with
// audit(2), with a Windows ETW provider, with a replay of a JSONL capture in a
// test — and no detection rule needs to change. It also means every rule can be
// tested against a struct literal, with no kernel, no privileges and no CI
// runner that supports BPF.
package events

// Syscall identifies which syscall an event came from.
//
// The numeric values mirror `enum ks_syscall` in bpf/event.h and must stay in
// lockstep with it. They are the only hand-maintained correspondence between
// the C and Go halves of the project — everything else is generated from BTF —
// so they are covered by a test that fails loudly if the two lists diverge.
type Syscall uint32

const (
	SysUnknown   Syscall = 0
	SysExecve    Syscall = 1
	SysExecveat  Syscall = 2
	SysOpenat    Syscall = 3
	SysSetuid    Syscall = 4
	SysSetgid    Syscall = 5
	SysSetresuid Syscall = 6
	SysSetresgid Syscall = 7
	SysPtrace    Syscall = 8
	SysSocket    Syscall = 9
	SysConnect   Syscall = 10
	SysDup2      Syscall = 11
	SysDup3      Syscall = 12
	SysCapset    Syscall = 13
)

// syscallNames maps each ID to the name a reader would expect to see in an
// alert — i.e. the libc/manpage name, not the kernel's internal symbol.
var syscallNames = map[Syscall]string{
	SysUnknown:   "unknown",
	SysExecve:    "execve",
	SysExecveat:  "execveat",
	SysOpenat:    "openat",
	SysSetuid:    "setuid",
	SysSetgid:    "setgid",
	SysSetresuid: "setresuid",
	SysSetresgid: "setresgid",
	SysPtrace:    "ptrace",
	SysSocket:    "socket",
	SysConnect:   "connect",
	SysDup2:      "dup2",
	SysDup3:      "dup3",
	SysCapset:    "capset",
}

// String returns the syscall name, or "unknown(N)" for an ID this build does
// not recognise.
//
// The fallback keeps the numeric value rather than collapsing to "unknown".
// If the kernel object and the Go binary ever get out of step — the exact
// situation where a monitoring tool must not lie quietly — the alert says
// "unknown(17)" and the mismatch is immediately diagnosable.
func (s Syscall) String() string {
	if name, ok := syscallNames[s]; ok {
		return name
	}
	return "unknown(" + itoa(uint64(s)) + ")"
}

// IsExecution reports whether the syscall replaces the process image.
// Both forms matter: execveat with AT_EMPTY_PATH is the standard fileless
// execution technique, so rules that only consider execve have a blind spot.
func (s Syscall) IsExecution() bool {
	return s == SysExecve || s == SysExecveat
}

// IsCredentialChange reports whether the syscall alters the process's user or
// group identity — the set the privilege-escalation rule cares about.
func (s Syscall) IsCredentialChange() bool {
	switch s {
	case SysSetuid, SysSetgid, SysSetresuid, SysSetresgid:
		return true
	}
	return false
}

// IsDup reports whether the syscall duplicates a file descriptor.
//
// dup2 and dup3 are equivalent for our purposes and callers should almost
// always treat them together: glibc implements dup2() on top of dup3(), and
// arm64 has no dup2 syscall at all, so a rule matching only dup2 would never
// fire on an ARM host.
func (s Syscall) IsDup() bool {
	return s == SysDup2 || s == SysDup3
}

// itoa is a tiny unsigned formatter used by String, kept local so this file
// does not pull in strconv for one call site on an error path.
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
