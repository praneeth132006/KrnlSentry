package ebpfloader

import (
	"fmt"
	"unsafe"

	"github.com/praneeth132006/KrnlSentry/events"
)

// eventSize is the exact wire size of one record, taken from the generated
// type rather than hard-coded. If bpf/event.h changes, this changes with it and
// the length check below keeps working.
var eventSize = int(unsafe.Sizeof(KrnlSentryEvent{}))

// parseRecord converts one raw ring buffer record into an events.Raw.
//
// WHY unsafe RATHER THAN encoding/binary
// ──────────────────────────────────────
// binary.Read on this struct would be correct but reflection-driven, costing
// hundreds of reflect calls per event to walk the nested [3][64]int8 array.
// openat alone fires thousands of times a second on an idle system, so that
// overhead lands directly on the ring buffer drain rate — and a slow drain is
// not merely inefficient here, it is dropped events.
//
// The cast is sound for three specific reasons:
//
//   - Layout. The generated struct carries structs.HostLayout, which tells the
//     compiler to lay it out exactly as the C compiler did. It was generated
//     from this object's own BTF, so it matches bpf/event.h by construction.
//
//   - Alignment. Ring buffer records are 8-byte aligned by the kernel, and
//     RawSample points into that mapping, so the pointer meets the struct's
//     alignment requirement.
//
//   - Lifetime. We copy every field out into an events.Raw before returning.
//     Nothing retains a pointer into the ring buffer, which matters because
//     that memory is reused as soon as the record is consumed — returning a
//     struct that aliased it would produce data that silently mutates.
//
// The length check is not a formality: a short record would otherwise read past
// the end of the mapping.
func parseRecord(b []byte) (events.Raw, error) {
	if len(b) < eventSize {
		return events.Raw{}, fmt.Errorf(
			"short event record: got %d bytes, want %d (kernel object and agent are out of step)",
			len(b), eventSize)
	}

	e := (*KrnlSentryEvent)(unsafe.Pointer(&b[0]))

	raw := events.Raw{
		Timestamp: e.Timestamp,
		PID:       e.Pid,
		TGID:      e.Tgid,
		UID:       e.Uid,
		GID:       e.Gid,
		PPID:      e.Ppid,
		SyscallID: e.SyscallId,
		Ret:       e.Ret,
		Arg0:      e.Arg0,
		Arg1:      e.Arg1,
		Arg2:      e.Arg2,
		Daddr:     e.Daddr,
		Dport:     e.Dport,
		Family:    e.Family,
		Flags:     e.Flags,
		Comm:      goString(e.Comm[:]),
		Path:      goString(e.Path[:]),
	}

	// Argc is bounded by MAX_ARGV in the C, but it arrives from kernel
	// memory and is used as a slice bound — clamp it rather than trust it.
	// A corrupted length here would be an out-of-range panic that takes the
	// whole agent down.
	argc := int(e.Argc)
	if argc > len(e.Argv) {
		argc = len(e.Argv)
	}

	if argc > 0 {
		raw.Argv = make([]string, 0, argc)
		for i := range argc {
			raw.Argv = append(raw.Argv, goString(e.Argv[i][:]))
		}
	}

	return raw, nil
}

// goString converts a NUL-terminated C char array into a Go string.
//
// The kernel writes char, which cgo-free Go renders as int8. Truncating at the
// first NUL is required: bpf_get_current_comm and bpf_probe_read_user_str both
// leave the remainder of the buffer as the zeros we memset, and converting the
// whole array would produce a string padded with NULs that compares unequal to
// the obvious literal — a bug that is invisible in printed output and breaks
// every path comparison in the detection rules.
func goString(b []int8) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}

	if n == 0 {
		return ""
	}

	// int8 and byte have identical representation, so this reinterprets the
	// slice header without copying the bytes. The subsequent string
	// conversion makes its own copy, so the result does not alias the ring
	// buffer.
	return string(unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), n))
}
