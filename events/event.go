package events

import (
	"fmt"
	"strings"
	"time"
)

// Raw is a kernel event as collected, before any interpretation.
//
// It is a flat mirror of `struct event` in bpf/event.h with C-isms removed:
// fixed-size char arrays become Go strings, the argv matrix becomes a slice.
// The collection layer's only job is to produce one of these; everything after
// that is pure computation.
//
// Keeping Raw separate from Event is what makes the decoding layer testable.
// A test constructs a Raw literal and asserts on the resulting Event, with no
// kernel and no eBPF anywhere in the picture.
type Raw struct {
	// Timestamp is nanoseconds since boot (CLOCK_MONOTONIC), straight from
	// bpf_ktime_get_ns(). Not a wall clock — see Event.Timestamp.
	Timestamp uint64

	PID  uint32 // kernel pid: the thread id
	TGID uint32 // kernel tgid: the process id userspace calls a PID
	UID  uint32
	GID  uint32
	PPID uint32

	SyscallID uint32

	Ret  int64
	Arg0 int64
	Arg1 int64
	Arg2 int64

	Daddr  uint32 // IPv4 destination, network byte order
	Dport  uint16 // network byte order
	Family uint16

	Flags uint32

	Comm string
	Path string
	Argv []string
}

// Event flag bits, mirroring the KS_FLAG_* macros in bpf/event.h.
const (
	// FlagSysExit marks an event from a sys_exit probe. On those, only Ret
	// and the identity fields carry meaning — the argument registers have
	// already been clobbered by the time the syscall returns.
	FlagSysExit uint32 = 1 << 0
)

// IsExit reports whether this event came from a syscall return probe.
func (r Raw) IsExit() bool { return r.Flags&FlagSysExit != 0 }

// Event is the canonical observation that the rest of the system operates on.
//
// This is the struct the detection engine sees, and the only one it is allowed
// to see. Note what is absent: no file descriptors into the ring buffer, no
// map handles, no reference to the probe that produced it.
type Event struct {
	// Timestamp is nanoseconds since boot, preserved exactly as the kernel
	// reported it. Rules that measure elapsed time — the reverse-shell
	// window, the state tracker's TTL — must use this rather than Wall.
	//
	// It is monotonic, so it cannot jump backwards when NTP steps the
	// clock. A wall-clock window would be a real bug: a backwards step
	// mid-capture makes a 2-second window briefly infinite, and a forwards
	// step silently expires a chain that was about to match.
	Timestamp uint64

	// Wall is Timestamp resolved to an absolute time, computed once at
	// startup from the boot instant. For humans and log files only.
	Wall time.Time

	PID  uint32 // the process id (kernel tgid) — what users mean by "PID"
	TID  uint32 // the thread id (kernel pid)
	TGID uint32 // same as PID; kept because the spec names both
	UID  uint32
	GID  uint32
	PPID uint32

	Comm string // process name, ≤15 chars + NUL as the kernel stores it

	// Syscall is the name, not the number. Rules read better matching on
	// "ptrace" than on 8, and the cost is one map lookup per event.
	Syscall string

	// SyscallID is retained alongside the name so rules can switch on a
	// constant without string comparison in the hot path.
	SyscallID Syscall

	// Args holds decoded, syscall-specific arguments. Values are strings
	// because this map is a presentation and matching surface, not a
	// calculation surface — anything a rule needs to compute on is
	// available as a typed field on the Event.
	Args map[string]string

	// ReturnValue is populated on sys_exit events; IsExit says whether it
	// means anything.
	ReturnValue int64
	IsExit      bool

	// Typed accessors for the fields rules actually compute on. These
	// duplicate entries in Args deliberately: a rule comparing an integer
	// should not be parsing a string it just formatted.
	Arg0, Arg1, Arg2 int64

	// Path is the execve/execveat filename or the openat pathname, exactly
	// as the calling process wrote it — possibly relative, possibly via a
	// symlink. It is the caller's *intent*, not a resolved inode. See the
	// README's limitations section on symlink evasion.
	Path string

	// Argv holds up to the first three execve arguments, for alert context.
	Argv []string

	// DestIP and DestPort describe a connect() target. Empty and zero for
	// non-network events and for address families we do not parse.
	DestIP   string
	DestPort uint16
	Family   uint16
}

// Decode turns a Raw kernel record into a fully interpreted Event.
//
// bootTime is the absolute instant the machine booted, captured once by the
// caller; it converts the kernel's monotonic timestamp into a wall clock. It is
// a parameter rather than a package-level value so that tests are deterministic
// and so that a replay tool can decode a historical capture against the boot
// time that capture was taken with.
func Decode(r Raw, bootTime time.Time) Event {
	sc := Syscall(r.SyscallID)

	ev := Event{
		Timestamp:   r.Timestamp,
		Wall:        bootTime.Add(time.Duration(r.Timestamp)),
		PID:         r.TGID,
		TID:         r.PID,
		TGID:        r.TGID,
		UID:         r.UID,
		GID:         r.GID,
		PPID:        r.PPID,
		Comm:        r.Comm,
		Syscall:     sc.String(),
		SyscallID:   sc,
		Args:        make(map[string]string, 4),
		ReturnValue: r.Ret,
		IsExit:      r.IsExit(),
		Arg0:        r.Arg0,
		Arg1:        r.Arg1,
		Arg2:        r.Arg2,
		Path:        r.Path,
		Argv:        r.Argv,
		Family:      r.Family,
	}

	// On a return probe the argument registers are already gone, so
	// decoding them would produce confident nonsense. Report the result and
	// stop.
	if ev.IsExit {
		ev.Args["ret"] = fmt.Sprintf("%d", r.Ret)
		if r.Ret < 0 {
			// Negative returns are -errno. Naming it turns "-13" into
			// something a reader can act on.
			ev.Args["error"] = errnoName(-r.Ret)
		}
		return ev
	}

	decodeArgs(&ev, r)
	return ev
}

// decodeArgs populates Args with the syscall-specific interpretation of the
// raw argument registers.
//
// Every branch here is a deliberate statement about which arguments are worth
// carrying. Arguments that are opaque user pointers we did not dereference are
// omitted rather than printed as hex addresses, which would be noise.
func decodeArgs(ev *Event, r Raw) {
	switch ev.SyscallID {
	case SysExecve:
		ev.Args["path"] = r.Path
		if len(r.Argv) > 0 {
			ev.Args["argv"] = strings.Join(r.Argv, " ")
		}

	case SysExecveat:
		ev.Args["path"] = r.Path
		ev.Args["dfd"] = formatDirfd(r.Arg0)
		ev.Args["flags"] = formatExecveatFlags(r.Arg1)
		if len(r.Argv) > 0 {
			ev.Args["argv"] = strings.Join(r.Argv, " ")
		}

	case SysOpenat:
		ev.Args["path"] = r.Path
		ev.Args["dfd"] = formatDirfd(r.Arg0)
		ev.Args["flags"] = formatOpenFlags(r.Arg1)
		// mode is only meaningful when O_CREAT or O_TMPFILE is set;
		// otherwise the kernel ignores it and it holds stack garbage.
		if r.Arg1&oCreat != 0 || r.Arg1&oTmpfile == oTmpfile {
			ev.Args["mode"] = fmt.Sprintf("0%o", r.Arg2&0o7777)
		}

	case SysSetuid:
		ev.Args["target_uid"] = formatID(r.Arg0)

	case SysSetgid:
		ev.Args["target_gid"] = formatID(r.Arg0)

	case SysSetresuid:
		ev.Args["ruid"] = formatID(r.Arg0)
		ev.Args["euid"] = formatID(r.Arg1)
		ev.Args["suid"] = formatID(r.Arg2)

	case SysSetresgid:
		ev.Args["rgid"] = formatID(r.Arg0)
		ev.Args["egid"] = formatID(r.Arg1)
		ev.Args["sgid"] = formatID(r.Arg2)

	case SysPtrace:
		ev.Args["request"] = PtraceRequestName(r.Arg0)
		ev.Args["target_pid"] = fmt.Sprintf("%d", r.Arg1)
		// The address only means something for the peek/poke family;
		// for ATTACH it is required to be zero and printing it invites
		// misreading.
		if isPtraceMemoryOp(r.Arg0) {
			ev.Args["addr"] = fmt.Sprintf("0x%x", uint64(r.Arg2))
		}

	case SysSocket:
		ev.Args["family"] = AddressFamilyName(uint16(r.Arg0))
		ev.Args["type"] = formatSocketType(r.Arg1)
		ev.Args["protocol"] = fmt.Sprintf("%d", r.Arg2)

	case SysConnect:
		ev.Args["fd"] = fmt.Sprintf("%d", r.Arg0)
		ev.Args["family"] = AddressFamilyName(r.Family)
		ev.DestPort = ntohs(r.Dport)
		if r.Daddr != 0 {
			ev.DestIP = formatIPv4(r.Daddr)
		}
		if ev.DestIP != "" {
			ev.Args["dest"] = fmt.Sprintf("%s:%d", ev.DestIP, ev.DestPort)
		} else if ev.DestPort != 0 {
			ev.Args["dest_port"] = fmt.Sprintf("%d", ev.DestPort)
		}

	case SysDup2:
		ev.Args["oldfd"] = fmt.Sprintf("%d", r.Arg0)
		ev.Args["newfd"] = formatStdFd(r.Arg1)

	case SysDup3:
		ev.Args["oldfd"] = fmt.Sprintf("%d", r.Arg0)
		ev.Args["newfd"] = formatStdFd(r.Arg1)
		if r.Arg2 != 0 {
			ev.Args["flags"] = fmt.Sprintf("0x%x", uint64(r.Arg2))
		}

	case SysCapset:
		// Both arguments are user pointers to capability structs that
		// the kernel program deliberately does not dereference. There
		// is nothing honest to put here; see the capset comment in
		// krnlsentry.bpf.c for why full capability diffing is a stretch
		// goal rather than a guess.
	}
}

// IsLoopback reports whether a connect() destination is a loopback address.
//
// Used to keep the reverse-shell rule from screaming during its own test
// suite: the demo scripts in test/ connect only to 127.0.0.1, and a rule that
// cannot distinguish that from a real egress is a rule that gets muted.
func (e Event) IsLoopback() bool {
	return strings.HasPrefix(e.DestIP, "127.") || e.DestIP == "::1"
}
