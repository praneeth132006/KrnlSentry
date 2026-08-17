package detect

import (
	"sync"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

func TestTrackerOnlyRecordsSequenceSyscalls(t *testing.T) {
	tr := NewTracker()

	// openat is the highest-volume probe and no sequence rule reads it.
	// Recording it would let the tracker's memory be dominated by data
	// nothing consumes.
	if h := tr.Record(makeEvent(events.SysOpenat, withPath("/tmp/x"))); h != nil {
		t.Error("openat was recorded; it participates in no sequence rule")
	}
	if h := tr.Record(makeEvent(events.SysSetuid)); h != nil {
		t.Error("setuid was recorded; it participates in no sequence rule")
	}

	if h := tr.Record(makeEvent(events.SysSocket)); h == nil {
		t.Error("socket was not recorded")
	}
}

func TestTrackerBoundsHistoryDepth(t *testing.T) {
	tr := NewTracker()

	// Far more events than the depth limit. A naive implementation that
	// resliced (h.entries = h.entries[1:]) would keep the backing array
	// growing forever even while len() looked correct.
	for i := range 500 {
		tr.Record(makeEvent(events.SysSocket,
			withPID(1),
			withTimestamp(time.Duration(i)*time.Millisecond)))
	}

	h := tr.Record(makeEvent(events.SysSocket, withPID(1), withTimestamp(500*time.Millisecond)))

	if got := len(h.Entries()); got > defaultHistoryDepth {
		t.Errorf("history holds %d entries, exceeds cap of %d", got, defaultHistoryDepth)
	}

	if got := cap(h.entries); got > defaultHistoryDepth*4 {
		t.Errorf("backing array grew to %d; entries are being resliced rather than compacted", got)
	}
}

func TestTrackerWindow(t *testing.T) {
	tr := NewTracker()

	for i := range 5 {
		tr.Record(makeEvent(events.SysSocket,
			withPID(1),
			withTimestamp(time.Duration(i)*time.Second)))
	}

	h := tr.Record(makeEvent(events.SysExecve, withPID(1), withTimestamp(5*time.Second)))

	// A 2-second window from t=5s should include t=4s and t=5s only.
	within := h.Within(uint64(5*time.Second), 2*time.Second)

	for _, e := range within {
		if e.Timestamp < uint64(3*time.Second) {
			t.Errorf("entry at %v is outside the 2s window ending at 5s",
				time.Duration(e.Timestamp))
		}
	}

	if len(within) == 0 {
		t.Error("window returned nothing; the most recent events should always be inside it")
	}
	if len(within) == len(h.Entries()) {
		t.Error("window returned every entry; older events were not excluded")
	}
}

func TestTrackerTTLEviction(t *testing.T) {
	tr := NewTracker()

	tr.Record(makeEvent(events.SysSocket, withPID(1), withTimestamp(0)))
	if tr.Len() != 1 {
		t.Fatalf("tracked %d processes, want 1", tr.Len())
	}

	// An event far in the future from a different process triggers a sweep,
	// which should evict the now-stale first process.
	future := time.Duration(defaultTTL) + time.Minute
	tr.Record(makeEvent(events.SysSocket, withPID(2), withTimestamp(future)))

	if tr.Len() != 1 {
		t.Errorf("tracked %d processes after TTL sweep, want 1 (the stale one should be gone)", tr.Len())
	}
}

func TestTrackerForget(t *testing.T) {
	tr := NewTracker()

	tr.Record(makeEvent(events.SysSocket, withPID(42)))
	tr.Forget(42)

	if tr.Len() != 0 {
		t.Errorf("tracked %d processes after Forget, want 0", tr.Len())
	}
}

func TestTrackerUpdatesCommAfterExec(t *testing.T) {
	// A process changes its name at execve. An alert reporting the pre-exec
	// name would point a reader at the wrong binary.
	tr := NewTracker()

	tr.Record(makeEvent(events.SysSocket, withPID(1), withComm("python3")))
	h := tr.Record(makeEvent(events.SysExecve, withPID(1), withComm("sh")))

	if h.Comm != "sh" {
		t.Errorf("Comm = %q after exec, want \"sh\"", h.Comm)
	}
}

func TestProcessHistoryNilSafe(t *testing.T) {
	// Record returns nil for untracked syscalls, so rules receive a nil
	// history routinely. They must not have to check.
	var h *ProcessHistory

	if got := h.Entries(); got != nil {
		t.Errorf("Entries() on nil = %v, want nil", got)
	}
	if got := h.Within(1000, time.Second); got != nil {
		t.Errorf("Within() on nil = %v, want nil", got)
	}
}

func TestTrackerConcurrentAccess(t *testing.T) {
	// The agent drives the tracker from one goroutine today. This test
	// exists so that stays true by design rather than by luck — run with
	// -race, it fails loudly if the locking is ever removed.
	tr := NewTracker()

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 200 {
				tr.Record(makeEvent(events.SysSocket,
					withPID(uint32(w)),
					withTimestamp(time.Duration(i)*time.Millisecond)))
				tr.Len()
			}
		}(worker)
	}
	wg.Wait()
}
