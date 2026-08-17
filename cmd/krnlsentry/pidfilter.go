package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/praneeth132006/KrnlSentry/events"
)

// pidFilter restricts monitoring to one process and its descendants.
//
// WHY THIS IS IN USER SPACE
// ─────────────────────────
// The obvious implementation is a BPF map of interesting PIDs consulted inside
// each probe, dropping uninteresting events before they ever reach the ring
// buffer. That is genuinely better — it is the difference between filtering
// 200k events/sec and producing 200k events/sec and then discarding them — and
// it is the top item in the README's future work.
//
// It is not what this does, for the reason stated in the spec: the collection
// layer stays free of policy so it can be swapped without touching anything
// else. The cost is real and is documented rather than hidden: with --pid, the
// kernel still emits every matching syscall on the system and this filter
// discards most of them.
//
// DESCENDANT TRACKING
// ───────────────────
// "and its children" cannot be answered from a single event, so the set is
// grown as processes appear. Two sources feed it:
//
//   - An initial walk of /proc, so processes that already existed when the
//     agent started are included. Without this, attaching to a running server
//     would monitor the parent and nothing it had already forked.
//   - Every subsequent event: if the event's PPID is in the set, its PID joins.
//     A newly forked child's first syscall carries its parent's PPID, so the
//     set extends down the tree as it grows.
//
// The gap this leaves is honest and small: a grandchild whose parent exited
// before we ever saw the parent gets re-parented to init and is lost. Closing
// it properly means tracing sched_process_fork, which is worth doing and is not
// part of the MVP probe set.
type pidFilter struct {
	root    uint32
	tracked map[uint32]bool
}

// newPIDFilter builds a filter rooted at pid, seeded from the current process
// tree.
func newPIDFilter(pid uint32) *pidFilter {
	f := &pidFilter{
		root:    pid,
		tracked: map[uint32]bool{pid: true},
	}

	f.seedFromProc()

	return f
}

// Allow reports whether an event is in scope, and records newly discovered
// descendants as a side effect.
func (f *pidFilter) Allow(ev events.Event) bool {
	if f.tracked[ev.PID] {
		return true
	}

	// A process whose parent we are watching becomes watched itself.
	if f.tracked[ev.PPID] {
		f.tracked[ev.PID] = true
		return true
	}

	return false
}

// Len reports how many processes are currently in scope.
func (f *pidFilter) Len() int { return len(f.tracked) }

// seedFromProc walks /proc and adds every existing descendant of the root.
//
// Best effort throughout: /proc entries vanish while being read (the process
// exited between readdir and open), and that is normal rather than an error
// worth reporting. A partially seeded filter still works — anything missed gets
// picked up by Allow the next time that process makes a syscall.
func (f *pidFilter) seedFromProc() {
	parents := make(map[uint32]uint32) // pid -> ppid

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a pid directory
		}

		ppid, ok := readPPID(uint32(pid))
		if !ok {
			continue
		}

		parents[uint32(pid)] = ppid
	}

	// Repeatedly sweep, adding any process whose parent is already tracked.
	// A single pass would miss grandchildren that /proc happened to list
	// before their parents; iterating to a fixed point is bounded by the
	// depth of the tree and costs nothing at this size.
	for {
		grew := false

		for pid, ppid := range parents {
			if f.tracked[pid] {
				continue
			}
			if f.tracked[ppid] {
				f.tracked[pid] = true
				grew = true
			}
		}

		if !grew {
			break
		}
	}
}

// readPPID extracts a process's parent pid from /proc/<pid>/stat.
//
// /proc/<pid>/stat is parsed rather than /proc/<pid>/status because it is a
// single line, but it has a notorious trap: field 2 is the executable name in
// parentheses, and that name can itself contain spaces and parentheses — a
// process really can be called "(evil) (name)". Splitting the line on spaces
// therefore mis-parses for hostile or merely unusual process names.
//
// Scanning to the *last* ')' first is the standard correct approach: everything
// after it is space-separated and unambiguous, with state as the first field
// and ppid as the second.
func readPPID(pid uint32) (uint32, bool) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return 0, false
	}

	line := string(data)

	close := strings.LastIndexByte(line, ')')
	if close < 0 || close+2 >= len(line) {
		return 0, false
	}

	fields := strings.Fields(line[close+2:])
	if len(fields) < 2 {
		return 0, false
	}

	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, false
	}

	return uint32(ppid), true
}
