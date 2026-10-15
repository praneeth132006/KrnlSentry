package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Record is the on-disk form of an Event: one JSON object per line in the
// --verbose capture, and the input format of --replay.
//
// It carries two layers. The decoded layer (timestamp, syscall, args) is for
// people reading the file. The typed layer (arg0..arg2, path, argv, dest_*) is
// what rules actually compute on, and it is what makes a capture *lossless*:
// replaying a file must reproduce exactly the alerts the live agent would have
// raised, which is impossible if a rule's input had to be re-parsed out of a
// presentation string.
//
// Field names are an on-disk contract. Adding a field is safe; renaming one
// strands every capture already written.
type Record struct {
	Timestamp string `json:"timestamp"`
	Monotonic uint64 `json:"monotonic_ns"`
	PID       uint32 `json:"pid"`
	TID       uint32 `json:"tid"`
	PPID      uint32 `json:"ppid"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Comm      string `json:"comm"`
	Syscall   string `json:"syscall"`
	Exit      bool   `json:"exit,omitempty"`
	Ret       int64  `json:"ret,omitempty"`

	Args map[string]string `json:"args,omitempty"`

	Arg0     int64    `json:"arg0,omitempty"`
	Arg1     int64    `json:"arg1,omitempty"`
	Arg2     int64    `json:"arg2,omitempty"`
	Path     string   `json:"path,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	DestIP   string   `json:"dest_ip,omitempty"`
	DestPort uint16   `json:"dest_port,omitempty"`
	Family   uint16   `json:"family,omitempty"`
}

// recordTimeLayout is millisecond RFC 3339 in UTC. Milliseconds are enough for
// a human-facing field; rules measure time with Monotonic, which is exact.
const recordTimeLayout = "2006-01-02T15:04:05.000Z"

// NewRecord converts an Event into its on-disk form.
func NewRecord(ev Event) Record {
	rec := Record{
		Timestamp: ev.Wall.UTC().Format(recordTimeLayout),
		Monotonic: ev.Timestamp,
		PID:       ev.PID,
		TID:       ev.TID,
		PPID:      ev.PPID,
		UID:       ev.UID,
		GID:       ev.GID,
		Comm:      ev.Comm,
		Syscall:   ev.Syscall,
		Exit:      ev.IsExit,
		Args:      ev.Args,
		Arg0:      ev.Arg0,
		Arg1:      ev.Arg1,
		Arg2:      ev.Arg2,
		Path:      ev.Path,
		Argv:      ev.Argv,
		DestIP:    ev.DestIP,
		DestPort:  ev.DestPort,
		Family:    ev.Family,
	}

	if ev.IsExit {
		rec.Ret = ev.ReturnValue
	}

	return rec
}

// Event reconstructs the Event a Record was written from.
//
// The syscall is looked up by name rather than stored as a number so that a
// capture stays readable and survives a renumbering of enum ks_syscall. An
// unrecognised name is an error: replaying "unknown(17)" as SysUnknown would
// let rules silently skip events the capture says happened.
func (r Record) Event() (Event, error) {
	sc, ok := ParseSyscall(r.Syscall)
	if !ok {
		return Event{}, fmt.Errorf("unknown syscall %q", r.Syscall)
	}

	wall, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		return Event{}, fmt.Errorf("bad timestamp %q: %w", r.Timestamp, err)
	}

	args := r.Args
	if args == nil {
		// Rules annotate Args in place (the reverse-shell rule adds its
		// chain evidence), so a nil map here would panic downstream.
		args = make(map[string]string, 4)
	}

	return Event{
		Timestamp:   r.Monotonic,
		Wall:        wall,
		PID:         r.PID,
		TID:         r.TID,
		TGID:        r.PID,
		UID:         r.UID,
		GID:         r.GID,
		PPID:        r.PPID,
		Comm:        r.Comm,
		Syscall:     sc.String(),
		SyscallID:   sc,
		Args:        args,
		ReturnValue: r.Ret,
		IsExit:      r.Exit,
		Arg0:        r.Arg0,
		Arg1:        r.Arg1,
		Arg2:        r.Arg2,
		Path:        r.Path,
		Argv:        r.Argv,
		DestIP:      r.DestIP,
		DestPort:    r.DestPort,
		Family:      r.Family,
	}, nil
}

// maxRecordLine bounds a single capture line. A record is a few hundred bytes;
// a megabyte means the input is not a capture, and failing beats buffering it.
const maxRecordLine = 1 << 20

// ReadRecords streams Events from a JSONL capture, calling fn for each one in
// file order.
//
// Blank lines are skipped. A malformed line is an error that names its line
// number rather than being skipped: a replay that quietly drops the one event
// completing a reverse-shell chain would report "nothing found" with full
// confidence, which is the failure mode this whole project is built to avoid.
// The one exception is a truncated *final* line, which is exactly what a
// capture looks like after the agent was killed mid-write, and is tolerated.
func ReadRecords(r io.Reader, fn func(Event) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxRecordLine)

	var (
		lineNo     int
		pendingErr error
	)

	for sc.Scan() {
		lineNo++

		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		// A bad line followed by more lines is corruption, not truncation.
		if pendingErr != nil {
			return pendingErr
		}

		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			pendingErr = fmt.Errorf("line %d: %w", lineNo, err)
			continue
		}

		ev, err := rec.Event()
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}

		if err := fn(ev); err != nil {
			return err
		}
	}

	return sc.Err()
}
