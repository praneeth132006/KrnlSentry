package detect

import (
	"strconv"
	"strings"
	"time"
)

// Alert deduplication.
//
// A process that opens /etc/shadow in a loop is one finding, not ten thousand.
// Without folding, it buries every other alert in the terminal and turns the
// JSONL log into a denial-of-service against whoever reads it — which, for a
// sufficiently patient attacker, is a feature: generate noise on one rule and
// act under cover of it on another.
//
// The policy is a fixed window per key, measured from the first emission rather
// than sliding on each repeat. Sliding would let a steady loop suppress itself
// forever; a fixed window guarantees the behaviour resurfaces at least once per
// window, with a count of how much was folded into it.

// maxDedupKeys bounds the deduplicator the same way the Tracker is bounded.
const maxDedupKeys = 16384

type dedupEntry struct {
	firstTS    uint64
	suppressed uint64
}

type deduper struct {
	window    uint64
	seen      map[string]*dedupEntry
	lastSweep uint64
	total     uint64
}

func newDeduper(window time.Duration) *deduper {
	if window <= 0 {
		return nil
	}
	return &deduper{
		window: uint64(window),
		seen:   make(map[string]*dedupEntry),
	}
}

// admit reports whether an alert should be emitted. When an alert resurfaces
// after its window, it carries the number of repeats that were folded since
// the last emission.
func (d *deduper) admit(a *Alert, now uint64) bool {
	if d == nil {
		return true
	}

	d.maybeSweep(now)

	key := dedupKey(a)

	e, ok := d.seen[key]
	if ok && now >= e.firstTS && now-e.firstTS < d.window {
		e.suppressed++
		d.total++
		return false
	}

	if ok {
		a.Suppressed = e.suppressed
		e.firstTS = now
		e.suppressed = 0
		return true
	}

	d.seen[key] = &dedupEntry{firstTS: now}
	return true
}

// dedupKey identifies "the same finding".
//
// Identity is the rule, the process, the technique and the argument that
// distinguishes one instance from another — the path opened, the ptrace target,
// the connect destination. Volatile arguments (a POKEDATA address, an fd
// number, the chain duration) are deliberately excluded: they change on every
// call and would make every repeat look new.
func dedupKey(a *Alert) string {
	var b strings.Builder

	b.WriteString(a.Rule)
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(a.PID), 10))
	b.WriteByte('|')
	b.WriteString(a.MitreID)
	b.WriteByte('|')
	b.WriteString(a.Syscall)

	for _, k := range []string{"path", "request", "target_pid", "target_uid", "target_gid", "euid", "egid", "chain_dest"} {
		if v, ok := a.Args[k]; ok {
			b.WriteByte('|')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
		}
	}

	return b.String()
}

// dedupRetain is how many windows a key with an unreported fold count is kept,
// so that a finding which resurfaces a little after its window still reports
// how much was folded. Keys with nothing folded go as soon as they expire.
const dedupRetain = 4

// maybeSweep drops expired keys once per window.
func (d *deduper) maybeSweep(now uint64) {
	if d.lastSweep != 0 && now-d.lastSweep < d.window && len(d.seen) < maxDedupKeys {
		return
	}
	d.lastSweep = now

	for k, e := range d.seen {
		if now <= e.firstTS {
			continue
		}
		age := now - e.firstTS
		if (e.suppressed == 0 && age >= d.window) || age >= dedupRetain*d.window {
			delete(d.seen, k)
		}
	}

	if len(d.seen) >= maxDedupKeys {
		d.seen = make(map[string]*dedupEntry, maxDedupKeys/2)
	}
}
