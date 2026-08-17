package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/praneeth132006/KrnlSentry/detect"
	"github.com/praneeth132006/KrnlSentry/events"
)

// JSONLSink appends alerts to a file as JSON Lines.
//
// JSONL rather than a JSON array because the file must be valid and complete
// at every instant. An array needs a closing bracket, which means a tool killed
// with SIGKILL — or a machine that loses power, which is exactly when you most
// want the log — leaves an unparseable file. With JSONL every complete line
// stands alone, and a truncated final line costs you one alert instead of all
// of them. It also streams: `tail -f alerts.jsonl | jq` works while the agent
// is still running.
type JSONLSink struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

// NewJSONLSink opens path for appending, creating it if necessary.
//
// Append, never truncate: restarting the agent must not destroy the previous
// run's alerts. Mode 0600 because these records name processes, users and file
// paths on the host — that is sensitive material and should not be world
// readable by default.
func NewJSONLSink(path string) (*JSONLSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening alert log %q: %w", path, err)
	}

	return &JSONLSink{
		f:    f,
		enc:  json.NewEncoder(f),
		path: path,
	}, nil
}

// Write appends one alert.
//
// Deliberately unbuffered — json.Encoder writes straight to the file on every
// call. A buffered writer would be faster and would also mean that the alerts
// leading up to a crash are the ones still sitting in the buffer when the
// process dies. For a security log that trade is not worth making; alert
// volume is low by construction, since anything high-volume is not an alert.
func (s *JSONLSink) Write(a *detect.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		return fmt.Errorf("alert log %q is closed", s.path)
	}

	if err := s.enc.Encode(a); err != nil {
		return fmt.Errorf("writing alert to %q: %w", s.path, err)
	}

	return nil
}

// Path returns the file being written, for startup logging.
func (s *JSONLSink) Path() string { return s.path }

// Close flushes and closes the file. Safe to call twice.
func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.f == nil {
		return nil
	}

	// Sync before close so that alerts survive a machine that loses power
	// moments after the agent is asked to stop.
	syncErr := s.f.Sync()
	closeErr := s.f.Close()
	s.f = nil

	if closeErr != nil {
		return fmt.Errorf("closing alert log %q: %w", s.path, closeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("syncing alert log %q: %w", s.path, syncErr)
	}

	return nil
}

// EventSink writes raw observed events, not alerts.
//
// This backs --verbose. It is a separate type from JSONLSink rather than a
// mode on it because the two must never share a file: mixing millions of
// routine syscalls into alerts.jsonl would destroy the property that makes that
// file useful, which is that every line in it is worth reading.
type EventSink struct {
	mu   sync.Mutex
	w    io.WriteCloser
	enc  *json.Encoder
	path string
}

// debugRecord is the on-disk shape of a raw event.
//
// A distinct type from events.Event so that the debug format can carry the
// decoded fields and omit the ones that are noise, without the internal Event
// struct growing JSON tags for a use case it does not own.
type debugRecord struct {
	Timestamp string            `json:"timestamp"`
	Monotonic uint64            `json:"monotonic_ns"`
	PID       uint32            `json:"pid"`
	TID       uint32            `json:"tid"`
	PPID      uint32            `json:"ppid"`
	UID       uint32            `json:"uid"`
	GID       uint32            `json:"gid"`
	Comm      string            `json:"comm"`
	Syscall   string            `json:"syscall"`
	Exit      bool              `json:"exit,omitempty"`
	Ret       int64             `json:"ret,omitempty"`
	Args      map[string]string `json:"args,omitempty"`
}

// NewEventSink opens a debug log for appending.
func NewEventSink(path string) (*EventSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening debug log %q: %w", path, err)
	}

	return &EventSink{
		w:    f,
		enc:  json.NewEncoder(f),
		path: path,
	}, nil
}

// WriteEvent appends one observed event.
func (s *EventSink) WriteEvent(ev events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.w == nil {
		return fmt.Errorf("debug log %q is closed", s.path)
	}

	rec := debugRecord{
		Timestamp: ev.Wall.UTC().Format("2006-01-02T15:04:05.000Z"),
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
	}

	if ev.IsExit {
		rec.Ret = ev.ReturnValue
	}

	if err := s.enc.Encode(rec); err != nil {
		return fmt.Errorf("writing event to %q: %w", s.path, err)
	}

	return nil
}

// Path returns the file being written.
func (s *EventSink) Path() string { return s.path }

// Close closes the debug log. Safe to call twice.
func (s *EventSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.w == nil {
		return nil
	}

	err := s.w.Close()
	s.w = nil

	if err != nil {
		return fmt.Errorf("closing debug log %q: %w", s.path, err)
	}

	return nil
}
