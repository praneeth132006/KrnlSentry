package events

import (
	"fmt"
	"strings"
)

// This file turns raw syscall argument integers into text a human can read and
// a rule can match on.
//
// A note on portability, since it is the subtle risk here: the constants below
// are the asm-generic values, which x86_64 and arm64 both use. They are *not*
// universal — alpha, parisc, sparc and mips each redefine parts of the open(2)
// flag space, and PTRACE_GETREGS/SETREGS do not exist on arm64 at all. Since
// this project targets x86_64 and arm64 (the two architectures the Makefile
// builds for), these are correct; a port to another architecture must revisit
// this file rather than assume it carries over.

// open(2) flags. Octal, as the kernel headers write them.
const (
	oAccmode   int64 = 0o3
	oRdonly    int64 = 0o0
	oWronly    int64 = 0o1
	oRdwr      int64 = 0o2
	oCreat     int64 = 0o100
	oExcl      int64 = 0o200
	oNoctty    int64 = 0o400
	oTrunc     int64 = 0o1000
	oAppend    int64 = 0o2000
	oNonblock  int64 = 0o4000
	oDsync     int64 = 0o10000
	oDirect    int64 = 0o40000
	oLargefile int64 = 0o100000
	oDirectory int64 = 0o200000
	oNofollow  int64 = 0o400000
	oNoatime   int64 = 0o1000000
	oCloexec   int64 = 0o2000000
	oPath      int64 = 0o10000000
	oTmpfile   int64 = 0o20200000 // __O_TMPFILE | O_DIRECTORY
)

// openFlagNames is ordered so the rendered string reads the way a developer
// would write the call, most significant behaviour first.
var openFlagNames = []struct {
	bit  int64
	name string
}{
	{oCreat, "O_CREAT"},
	{oExcl, "O_EXCL"},
	{oTrunc, "O_TRUNC"},
	{oAppend, "O_APPEND"},
	{oNoctty, "O_NOCTTY"},
	{oNonblock, "O_NONBLOCK"},
	{oDsync, "O_DSYNC"},
	{oDirect, "O_DIRECT"},
	{oLargefile, "O_LARGEFILE"},
	{oDirectory, "O_DIRECTORY"},
	{oNofollow, "O_NOFOLLOW"},
	{oNoatime, "O_NOATIME"},
	{oCloexec, "O_CLOEXEC"},
	{oPath, "O_PATH"},
}

// formatOpenFlags renders openat's flags as "O_RDONLY|O_CLOEXEC".
//
// The low two bits are an access *mode* (a value, not a bitmask), so they are
// decoded separately — treating O_RDWR as two flags OR'd together would be
// wrong and would print "O_WRONLY|O_RDONLY" for a read-write open.
//
// O_TMPFILE is checked before the bit loop because it is a compound constant
// that includes O_DIRECTORY; without the special case, an O_TMPFILE open would
// render misleadingly as a directory open.
func formatOpenFlags(flags int64) string {
	var parts []string

	switch flags & oAccmode {
	case oRdonly:
		parts = append(parts, "O_RDONLY")
	case oWronly:
		parts = append(parts, "O_WRONLY")
	case oRdwr:
		parts = append(parts, "O_RDWR")
	default:
		parts = append(parts, "O_ACCMODE_INVALID")
	}

	remaining := flags &^ oAccmode

	if remaining&oTmpfile == oTmpfile {
		parts = append(parts, "O_TMPFILE")
		remaining &^= oTmpfile
	}

	for _, f := range openFlagNames {
		if remaining&f.bit == f.bit {
			parts = append(parts, f.name)
			remaining &^= f.bit
		}
	}

	// Anything left is a flag this build does not know. Show it as hex
	// rather than dropping it: silently discarding bits from a security
	// tool's output is how blind spots are born.
	if remaining != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", uint64(remaining)))
	}

	return strings.Join(parts, "|")
}

// *at() special directory fd, and execveat/openat resolution flags.
const (
	atFdcwd           int64 = -100
	atSymlinkNofollow int64 = 0x100
	atEmptyPath       int64 = 0x1000
)

// formatDirfd renders the dirfd argument of the *at() syscalls.
// AT_FDCWD is by far the common case and deserves its name rather than "-100".
func formatDirfd(fd int64) string {
	if fd == atFdcwd {
		return "AT_FDCWD"
	}
	return fmt.Sprintf("%d", fd)
}

// formatExecveatFlags renders execveat's flags.
//
// AT_EMPTY_PATH is called out explicitly because it is the interesting one:
// combined with a memfd, it executes a binary that exists only in memory and
// has no path on disk. That is the standard fileless-execution technique, and
// seeing the flag named in an alert is what makes it recognisable.
func formatExecveatFlags(flags int64) string {
	if flags == 0 {
		return "0"
	}

	var parts []string
	if flags&atEmptyPath != 0 {
		parts = append(parts, "AT_EMPTY_PATH")
	}
	if flags&atSymlinkNofollow != 0 {
		parts = append(parts, "AT_SYMLINK_NOFOLLOW")
	}

	known := atEmptyPath | atSymlinkNofollow
	if rest := flags &^ known; rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", uint64(rest)))
	}

	return strings.Join(parts, "|")
}

// ptrace(2) request numbers.
//
// The 0x42xx block are the "modern" requests added later; note that on arm64
// the classic PTRACE_GETREGS/SETREGS (12/13) are *not* implemented and
// PTRACE_GETREGSET/SETREGSET (0x4204/0x4205) are used instead. Any rule that
// looks for register hijacking must cover both, or it will simply never fire on
// ARM. See PtraceIsInjection.
const (
	PtraceTraceme    int64 = 0
	PtracePeektext   int64 = 1
	PtracePeekdata   int64 = 2
	PtracePeekuser   int64 = 3
	PtracePoketext   int64 = 4
	PtracePokedata   int64 = 5
	PtracePokeuser   int64 = 6
	PtraceCont       int64 = 7
	PtraceKill       int64 = 8
	PtraceSinglestep int64 = 9
	PtraceGetregs    int64 = 12
	PtraceSetregs    int64 = 13
	PtraceGetfpregs  int64 = 14
	PtraceSetfpregs  int64 = 15
	PtraceAttach     int64 = 16
	PtraceDetach     int64 = 17
	PtraceSyscall    int64 = 24
	PtraceSetoptions int64 = 0x4200
	PtraceGetregset  int64 = 0x4204
	PtraceSetregset  int64 = 0x4205
	PtraceSeize      int64 = 0x4206
	PtraceInterrupt  int64 = 0x4207
	PtraceListen     int64 = 0x4208
)

var ptraceRequestNames = map[int64]string{
	PtraceTraceme:    "PTRACE_TRACEME",
	PtracePeektext:   "PTRACE_PEEKTEXT",
	PtracePeekdata:   "PTRACE_PEEKDATA",
	PtracePeekuser:   "PTRACE_PEEKUSER",
	PtracePoketext:   "PTRACE_POKETEXT",
	PtracePokedata:   "PTRACE_POKEDATA",
	PtracePokeuser:   "PTRACE_POKEUSER",
	PtraceCont:       "PTRACE_CONT",
	PtraceKill:       "PTRACE_KILL",
	PtraceSinglestep: "PTRACE_SINGLESTEP",
	PtraceGetregs:    "PTRACE_GETREGS",
	PtraceSetregs:    "PTRACE_SETREGS",
	PtraceGetfpregs:  "PTRACE_GETFPREGS",
	PtraceSetfpregs:  "PTRACE_SETFPREGS",
	PtraceAttach:     "PTRACE_ATTACH",
	PtraceDetach:     "PTRACE_DETACH",
	PtraceSyscall:    "PTRACE_SYSCALL",
	PtraceSetoptions: "PTRACE_SETOPTIONS",
	PtraceGetregset:  "PTRACE_GETREGSET",
	PtraceSetregset:  "PTRACE_SETREGSET",
	PtraceSeize:      "PTRACE_SEIZE",
	PtraceInterrupt:  "PTRACE_INTERRUPT",
	PtraceListen:     "PTRACE_LISTEN",
}

// PtraceRequestName returns the symbolic name of a ptrace request.
func PtraceRequestName(req int64) string {
	if name, ok := ptraceRequestNames[req]; ok {
		return name
	}
	return fmt.Sprintf("PTRACE_UNKNOWN(%d)", req)
}

// isPtraceMemoryOp reports whether the request's addr argument refers to a
// memory location worth recording.
func isPtraceMemoryOp(req int64) bool {
	switch req {
	case PtracePeektext, PtracePeekdata, PtracePeekuser,
		PtracePoketext, PtracePokedata, PtracePokeuser:
		return true
	}
	return false
}

// Address families.
const (
	AFUnix    uint16 = 1
	AFInet    uint16 = 2
	AFInet6   uint16 = 10
	AFNetlink uint16 = 16
	AFPacket  uint16 = 17
)

var addressFamilyNames = map[uint16]string{
	0:         "AF_UNSPEC",
	AFUnix:    "AF_UNIX",
	AFInet:    "AF_INET",
	AFInet6:   "AF_INET6",
	AFNetlink: "AF_NETLINK",
	AFPacket:  "AF_PACKET",
}

// AddressFamilyName returns the symbolic name of an address family.
func AddressFamilyName(f uint16) string {
	if name, ok := addressFamilyNames[f]; ok {
		return name
	}
	return fmt.Sprintf("AF_UNKNOWN(%d)", f)
}

// socket(2) types and the flags that may be OR'd into the type argument.
const (
	sockStream    int64 = 1
	sockDgram     int64 = 2
	sockRaw       int64 = 3
	sockSeqpacket int64 = 5
	sockNonblock  int64 = 0o4000
	sockCloexec   int64 = 0o2000000
)

// formatSocketType renders socket()'s type argument, which is a base type with
// optional flags OR'd in — masking them off first is required, or SOCK_STREAM
// created with SOCK_CLOEXEC would fail to match SOCK_STREAM at all.
func formatSocketType(t int64) string {
	base := t &^ (sockNonblock | sockCloexec)

	var name string
	switch base {
	case sockStream:
		name = "SOCK_STREAM"
	case sockDgram:
		name = "SOCK_DGRAM"
	case sockRaw:
		name = "SOCK_RAW"
	case sockSeqpacket:
		name = "SOCK_SEQPACKET"
	default:
		name = fmt.Sprintf("SOCK_UNKNOWN(%d)", base)
	}

	parts := []string{name}
	if t&sockNonblock != 0 {
		parts = append(parts, "SOCK_NONBLOCK")
	}
	if t&sockCloexec != 0 {
		parts = append(parts, "SOCK_CLOEXEC")
	}

	return strings.Join(parts, "|")
}

// StdFdName returns "stdin"/"stdout"/"stderr" for descriptors 0, 1 and 2.
// The empty string means the fd is not one of the standard streams.
func StdFdName(fd int64) string {
	switch fd {
	case 0:
		return "stdin"
	case 1:
		return "stdout"
	case 2:
		return "stderr"
	}
	return ""
}

// formatStdFd renders a dup2/dup3 target, naming the standard streams.
// "1 (stdout)" is immediately meaningful in an alert where a bare "1" is not.
func formatStdFd(fd int64) string {
	if name := StdFdName(fd); name != "" {
		return fmt.Sprintf("%d (%s)", fd, name)
	}
	return fmt.Sprintf("%d", fd)
}

// formatID renders a uid/gid argument.
//
// (uid_t)-1 is the documented "leave this one unchanged" sentinel for the
// setres*id family. Rendering it as "unchanged" rather than "4294967295" or
// "-1" is the difference between an alert that explains itself and one that
// looks like a bug in the tool.
func formatID(id int64) string {
	if id == -1 {
		return "unchanged"
	}
	return fmt.Sprintf("%d", id)
}

// formatIPv4 renders a network-byte-order IPv4 address as dotted quad.
//
// The address arrives as it sat in the sockaddr — big endian — so the octets
// are extracted from least significant upward. Doing this by hand rather than
// via net.IP avoids a conversion allocation on a per-event path.
func formatIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xff,
		(addr>>8)&0xff,
		(addr>>16)&0xff,
		(addr>>24)&0xff)
}

// ntohs converts a network-byte-order 16-bit value to host order.
//
// Written as an explicit byte swap rather than an encoding/binary call because
// the value's endianness is a property of the wire format, not of the host: on
// a hypothetical big-endian host this must still swap, and binary.BigEndian
// applied to an already-decoded uint16 would not.
func ntohs(v uint16) uint16 {
	return v<<8 | v>>8
}

// errnoNames covers the errnos these syscalls realistically return. Anything
// outside the list is rendered numerically rather than guessed at.
var errnoNames = map[int64]string{
	1:   "EPERM",
	2:   "ENOENT",
	3:   "ESRCH",
	4:   "EINTR",
	5:   "EIO",
	9:   "EBADF",
	11:  "EAGAIN",
	12:  "ENOMEM",
	13:  "EACCES",
	14:  "EFAULT",
	16:  "EBUSY",
	17:  "EEXIST",
	20:  "ENOTDIR",
	21:  "EISDIR",
	22:  "EINVAL",
	24:  "EMFILE",
	28:  "ENOSPC",
	32:  "EPIPE",
	38:  "ENOSYS",
	40:  "ELOOP",
	97:  "EAFNOSUPPORT",
	98:  "EADDRINUSE",
	99:  "EADDRNOTAVAIL",
	101: "ENETUNREACH",
	103: "ECONNABORTED",
	104: "ECONNRESET",
	110: "ETIMEDOUT",
	111: "ECONNREFUSED",
	113: "EHOSTUNREACH",
	114: "EALREADY",
	115: "EINPROGRESS",
}

// errnoName maps a positive errno to its symbolic name.
func errnoName(errno int64) string {
	if name, ok := errnoNames[errno]; ok {
		return name
	}
	return fmt.Sprintf("errno %d", errno)
}
