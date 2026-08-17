package detect

import (
	"sync"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Some detections are not properties of a single syscall. A reverse shell is
// four ordinary syscalls in a particular order within a short window — each one
// individually is something every network client on the machine does. Detecting
// it needs memory, and this file is that memory.
//
// The design constraint is that this runs on every event on a busy system, so
// it must be bounded in three dimensions at once: how many processes are
// remembered, how much is remembered per process, and how long anything is
// remembered for. An unbounded version is a memory leak that takes hours to
// show up and takes down the monitor rather than the malware.

// Tracker defaults. Chosen to comfortably contain the sequences we look for
// while keeping worst-case memory in the low megabytes.
const (
	// defaultHistoryDepth caps entries per process. A reverse-shell chain
	// is 5-6 syscalls; 32 leaves room for interleaved unrelated activity
	// without letting a chatty process grow without limit.
	defaultHistoryDepth = 32

	// defaultTTL is how long a silent process is remembered. It must exceed
	// the longest rule window (2s by default) by a wide margin, or a chain
	// could be evicted midway through matching.
	defaultTTL = 30 * time.Second

	// defaultSweepInterval bounds how often eviction runs. Sweeping on
	// every event would be O(processes) per event; this amortises it.
	defaultSweepInterval = 5 * time.Second

	// defaultMaxProcesses is a hard ceiling on tracked processes. Reaching
	// it forces an immediate sweep. With the depth above this bounds the
	// tracker at roughly 8192 × 32 entries — a few tens of MB worst case,
	// on a system that would have to be forking pathologically to get there.
	defaultMaxProcesses = 8192
)

// HistoryEntry is one remembered syscall.
//
// Deliberately much smaller than an events.Event: it keeps only what sequence
// rules examine. Retaining full events — with their maps, paths and argv
// slices — would multiply the tracker's memory by an order of magnitude for
// data no rule reads.
type HistoryEntry struct {
	Syscall   events.Syscall
	Timestamp uint64 // monotonic ns, matching events.Event.Timestamp
	IsExit    bool

	Arg0 int64
	Arg1 int64
	Ret  int64

	DestIP   string
	DestPort uint16
}

// ProcessHistory is the recent interesting activity of one process.
//
// Entries are append-ordered, therefore time-ordered — which holds only because
// the collector uses a BPF ring buffer rather than a per-CPU perf buffer. With
// per-CPU delivery, events from different cores could arrive out of order and
// every sequence rule below would be subtly wrong.
type ProcessHistory struct {
	PID      uint32
	Comm     string
	entries  []HistoryEntry
	lastSeen uint64
}

// Entries returns the recorded history, oldest first.
//
// The slice is the tracker's own backing array, not a copy. Callers are rules,
// which only read — copying on every event to defend against a hypothetical
// misbehaving rule would cost more than it protects.
func (h *ProcessHistory) Entries() []HistoryEntry {
	if h == nil {
		return nil
	}
	return h.entries
}

// Within returns the entries recorded no earlier than window before now.
//
// Both bounds come from the kernel's monotonic clock, so this cannot be
// distorted by an NTP step the way a wall-clock comparison could.
func (h *ProcessHistory) Within(now uint64, window time.Duration) []HistoryEntry {
	if h == nil || len(h.entries) == 0 {
		return nil
	}

	cutoff := uint64(0)
	if w := uint64(window); now > w {
		cutoff = now - w
	}

	// Entries are time-ordered, so walk back from the end and stop at the
	// first one that is too old.
	start := len(h.entries)
	for start > 0 && h.entries[start-1].Timestamp >= cutoff {
		start--
	}

	return h.entries[start:]
}

// Tracker keeps bounded per-process history with TTL eviction.
//
// Safe for concurrent use. The agent currently drives it from a single
// goroutine, but a tracker that is only safe by accident of its caller is a
// trap for the next person who adds a worker pool.
type Tracker struct {
	mu    sync.Mutex
	procs map[uint32]*ProcessHistory

	depth        int
	ttl          time.Duration
	sweepEvery   time.Duration
	maxProcesses int

	lastSweep uint64
}

// NewTracker returns a Tracker with the default bounds.
func NewTracker() *Tracker {
	return &Tracker{
		procs:        make(map[uint32]*ProcessHistory),
		depth:        defaultHistoryDepth,
		ttl:          defaultTTL,
		sweepEvery:   defaultSweepInterval,
		maxProcesses: defaultMaxProcesses,
	}
}

// tracked reports whether an event is worth remembering.
//
// Only syscalls that participate in a sequence rule are stored. openat is the
// highest-volume probe by far and no sequence rule reads it, so recording it
// would dominate the tracker's memory to no purpose. If a future rule needs
// file-access history, this is the one place to change.
func tracked(sc events.Syscall) bool {
	switch sc {
	case events.SysSocket, events.SysConnect, events.SysDup2, events.SysDup3,
		events.SysExecve, events.SysExecveat:
		return true
	}
	return false
}

// Record files an event against its process and returns that process's history
// including the new event.
//
// Returns nil for syscalls no sequence rule uses, so callers must handle a nil
// history — which they do, since ProcessHistory's methods are nil-safe.
func (t *Tracker) Record(ev events.Event) *ProcessHistory {
	if !tracked(ev.SyscallID) {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.maybeSweep(ev.Timestamp)

	h, ok := t.procs[ev.PID]
	if !ok {
		h = &ProcessHistory{
			PID:     ev.PID,
			Comm:    ev.Comm,
			entries: make([]HistoryEntry, 0, 8),
		}
		t.procs[ev.PID] = h
	}

	// Keep comm fresh: after an execve the process name changes, and an
	// alert reporting the pre-exec name would point at the wrong binary.
	h.Comm = ev.Comm
	h.lastSeen = ev.Timestamp

	h.entries = append(h.entries, HistoryEntry{
		Syscall:   ev.SyscallID,
		Timestamp: ev.Timestamp,
		IsExit:    ev.IsExit,
		Arg0:      ev.Arg0,
		Arg1:      ev.Arg1,
		Ret:       ev.ReturnValue,
		DestIP:    ev.DestIP,
		DestPort:  ev.DestPort,
	})

	// Trim to depth by dropping the oldest entries. Copying down rather
	// than reslicing keeps the backing array from growing forever, which a
	// naive `h.entries = h.entries[1:]` would do.
	if len(h.entries) > t.depth {
		excess := len(h.entries) - t.depth
		h.entries = append(h.entries[:0], h.entries[excess:]...)
	}

	return h
}

// Forget drops a process's history.
//
// Called when a process exits, so that a recycled PID cannot inherit the
// previous occupant's syscall history and trigger a phantom sequence match.
func (t *Tracker) Forget(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.procs, pid)
}

// Len reports how many processes are currently tracked. Used by tests and by
// the periodic stats line.
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs)
}

// maybeSweep evicts stale processes, at most once per sweepEvery.
//
// Caller must hold t.mu.
//
// There is no background goroutine doing this on a timer, deliberately: with no
// events arriving there is nothing to evict that matters, and a ticker would
// wake an idle machine forever. Sweeping on the event path ties the work to the
// load that creates it.
func (t *Tracker) maybeSweep(now uint64) {
	overCapacity := len(t.procs) >= t.maxProcesses

	if !overCapacity {
		if t.lastSweep != 0 && now-t.lastSweep < uint64(t.sweepEvery) {
			return
		}
	}

	t.lastSweep = now

	ttl := uint64(t.ttl)
	for pid, h := range t.procs {
		// now can be less than lastSeen only if timestamps went
		// backwards, which the monotonic clock forbids; the guard keeps
		// the subtraction from wrapping if it ever happened anyway.
		if now > h.lastSeen && now-h.lastSeen > ttl {
			delete(t.procs, pid)
		}
	}

	// If a genuine burst of live processes keeps us at the ceiling, evicting
	// only expired entries is not enough. Dropping everything is crude but
	// bounded and self-healing: histories rebuild within one window, and the
	// alternative — an unbounded map — takes the monitor down entirely.
	if len(t.procs) >= t.maxProcesses {
		t.procs = make(map[uint32]*ProcessHistory, t.maxProcesses/2)
	}
}
