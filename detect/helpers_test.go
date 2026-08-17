package detect

import (
	"io/fs"
	"os"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Test helpers.
//
// The point of this file is that it needs no kernel, no root and no eBPF. Every
// rule below is exercised by constructing an events.Event literal, which is
// only possible because detect/ depends on nothing but events/ and the standard
// library. That constraint is the reason the architecture separates collection
// from detection.

var testBoot = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

// eventOpt mutates an event during construction.
type eventOpt func(*events.Event)

// makeEvent builds a decoded event the way the collector would have produced
// it — including running the real argument decoder, so tests exercise the same
// path production does rather than a hand-filled Args map.
func makeEvent(sc events.Syscall, opts ...eventOpt) events.Event {
	raw := events.Raw{
		Timestamp: uint64(time.Second),
		PID:       1000,
		TGID:      1000,
		UID:       1000,
		GID:       1000,
		PPID:      900,
		SyscallID: uint32(sc),
		Comm:      "testproc",
	}

	ev := events.Decode(raw, testBoot)

	for _, opt := range opts {
		opt(&ev)
	}

	return ev
}

// makeRawEvent builds an event from an explicit Raw, for cases where the
// argument decoding itself is part of what is being tested.
func makeRawEvent(raw events.Raw, opts ...eventOpt) events.Event {
	ev := events.Decode(raw, testBoot)
	for _, opt := range opts {
		opt(&ev)
	}
	return ev
}

func withUID(uid uint32) eventOpt {
	return func(e *events.Event) { e.UID = uid }
}

func withComm(comm string) eventOpt {
	return func(e *events.Event) { e.Comm = comm }
}

func withPID(pid uint32) eventOpt {
	return func(e *events.Event) { e.PID = pid; e.TGID = pid }
}

func withPath(path string) eventOpt {
	return func(e *events.Event) {
		e.Path = path
		e.Args["path"] = path
	}
}

func withArgs(a0, a1, a2 int64) eventOpt {
	return func(e *events.Event) { e.Arg0, e.Arg1, e.Arg2 = a0, a1, a2 }
}

func withTimestamp(d time.Duration) eventOpt {
	return func(e *events.Event) {
		e.Timestamp = uint64(d)
		e.Wall = testBoot.Add(d)
	}
}

// testContext builds a rule Context with the default configuration and a Stat
// that reports every file as an ordinary non-setuid regular file.
func testContext(ev events.Event, opts ...func(*Config)) Context {
	cfg := DefaultConfig()
	cfg.Stat = statAlways(0o755)
	cfg.SelfPID = 0 // never suppress the test event

	for _, opt := range opts {
		opt(&cfg)
	}

	return Context{Event: ev, Config: &cfg}
}

// ── Fake filesystem ─────────────────────────────────────────────────────────
//
// Injecting Stat is what makes the setuid-exec rule testable at all. Creating a
// genuine setuid binary requires root, which would mean this test could not run
// in CI, on a developer laptop, or in a container without --privileged.

// fakeFileInfo is a minimal fs.FileInfo carrying only the mode, which is the
// only field the rule reads.
type fakeFileInfo struct {
	mode fs.FileMode
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return testBoot }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// statAlways returns a StatFunc reporting the given mode for every path.
func statAlways(mode fs.FileMode) StatFunc {
	return func(string) (fs.FileInfo, error) {
		return fakeFileInfo{mode: mode}, nil
	}
}

// statMissing returns a StatFunc that always fails, standing in for a binary
// that was replaced or unlinked between the execve and our lookup.
func statMissing() StatFunc {
	return func(path string) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
	}
}
