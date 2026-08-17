package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// feedChain drives events through a real Engine, which is the only honest way
// to test a sequence rule: the tracker must record them in order exactly as it
// would in production, and the rule must read that history back.
//
// Returns every alert produced by the final event.
func feedChain(t *testing.T, cfg Config, evs ...events.Event) []*Alert {
	t.Helper()

	engine, err := NewEngine(cfg, []string{RuleNameReverseShell})
	if err != nil {
		t.Fatalf("building engine: %v", err)
	}

	var last []*Alert
	for _, ev := range evs {
		last = engine.Evaluate(ev)
	}

	return last
}

// chainEvents builds the canonical reverse-shell sequence.
func chainEvents(pid uint32, socketFD int64, redirect []int64, start time.Duration, spacing time.Duration) []events.Event {
	at := start
	next := func() time.Duration {
		at += spacing
		return at
	}

	evs := []events.Event{
		makeEvent(events.SysSocket, withPID(pid), withTimestamp(next()), withArgs(2, 1, 6)),
	}

	// socket() return, carrying the allocated descriptor.
	exit := makeRawEvent(events.Raw{
		SyscallID: uint32(events.SysSocket),
		TGID:      pid,
		PID:       pid,
		Flags:     events.FlagSysExit,
		Ret:       socketFD,
		Timestamp: uint64(next()),
	})
	evs = append(evs, exit)

	connect := makeRawEvent(events.Raw{
		SyscallID: uint32(events.SysConnect),
		TGID:      pid,
		PID:       pid,
		Family:    events.AFInet,
		Daddr:     0x0100007f, // 127.0.0.1
		Dport:     0x5c11,     // 4444
		Arg0:      socketFD,
		Timestamp: uint64(next()),
	})
	evs = append(evs, connect)

	for _, fd := range redirect {
		evs = append(evs, makeEvent(events.SysDup2,
			withPID(pid), withTimestamp(next()), withArgs(socketFD, fd, 0)))
	}

	evs = append(evs, makeEvent(events.SysExecve,
		withPID(pid), withTimestamp(next()), withPath("/bin/sh")))

	return evs
}

func TestReverseShellChain(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SelfPID = 0
	cfg.Stat = statAlways(0o755)

	alerts := feedChain(t, cfg, chainEvents(5000, 3, []int64{0, 1, 2}, 0, 10*time.Millisecond)...)

	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}

	a := alerts[0]

	if a.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL", a.Severity)
	}
	if a.MitreID != "T1059" {
		t.Errorf("MitreID = %q, want T1059", a.MitreID)
	}
	if got := a.Args["chain_dest"]; got != "127.0.0.1:4444" {
		t.Errorf("chain_dest = %q, want 127.0.0.1:4444", got)
	}
	// The strongest part of the evidence: the descriptor duplicated onto the
	// standard streams is the one socket() returned, not a coincidental
	// redirection of an unrelated file.
	if got := a.Args["chain_socket_fd_confirmed"]; got != "true" {
		t.Errorf("chain_socket_fd_confirmed = %q, want true", got)
	}
	if !strings.Contains(a.Args["chain_redirected"], "stdin") {
		t.Errorf("chain_redirected = %q, expected it to name the standard streams", a.Args["chain_redirected"])
	}
}

func TestReverseShellNegativeCases(t *testing.T) {
	baseCfg := func() Config {
		c := DefaultConfig()
		c.SelfPID = 0
		c.Stat = statAlways(0o755)
		return c
	}

	t.Run("only one redirected fd is not enough", func(t *testing.T) {
		// A single redirection is what ordinary programs do when they
		// send output to a file. Two is where it stops being ordinary.
		alerts := feedChain(t, baseCfg(),
			chainEvents(5001, 3, []int64{1}, 0, 10*time.Millisecond)...)
		if len(alerts) != 0 {
			t.Fatalf("got %d alerts, want 0", len(alerts))
		}
	})

	t.Run("redirecting non-standard fds is not a shell", func(t *testing.T) {
		alerts := feedChain(t, baseCfg(),
			chainEvents(5002, 3, []int64{7, 8, 9}, 0, 10*time.Millisecond)...)
		if len(alerts) != 0 {
			t.Fatalf("got %d alerts, want 0", len(alerts))
		}
	})

	t.Run("no connect means no chain", func(t *testing.T) {
		pid := uint32(5003)
		evs := []events.Event{
			makeEvent(events.SysSocket, withPID(pid), withTimestamp(10*time.Millisecond)),
			makeEvent(events.SysDup2, withPID(pid), withTimestamp(20*time.Millisecond), withArgs(3, 0, 0)),
			makeEvent(events.SysDup2, withPID(pid), withTimestamp(30*time.Millisecond), withArgs(3, 1, 0)),
			makeEvent(events.SysExecve, withPID(pid), withTimestamp(40*time.Millisecond), withPath("/bin/sh")),
		}
		if alerts := feedChain(t, baseCfg(), evs...); len(alerts) != 0 {
			t.Fatalf("got %d alerts, want 0", len(alerts))
		}
	})

	t.Run("dup2 before connect does not count", func(t *testing.T) {
		// Ordering is the whole rule. A process that redirects first and
		// dials later is not performing this pattern.
		pid := uint32(5004)
		evs := []events.Event{
			makeEvent(events.SysSocket, withPID(pid), withTimestamp(10*time.Millisecond)),
			makeEvent(events.SysDup2, withPID(pid), withTimestamp(20*time.Millisecond), withArgs(3, 0, 0)),
			makeEvent(events.SysDup2, withPID(pid), withTimestamp(30*time.Millisecond), withArgs(3, 1, 0)),
			makeRawEvent(events.Raw{
				SyscallID: uint32(events.SysConnect), TGID: pid, PID: pid,
				Family: events.AFInet, Daddr: 0x0100007f, Dport: 0x5c11,
				Timestamp: uint64(40 * time.Millisecond),
			}),
			makeEvent(events.SysExecve, withPID(pid), withTimestamp(50*time.Millisecond), withPath("/bin/sh")),
		}
		if alerts := feedChain(t, baseCfg(), evs...); len(alerts) != 0 {
			t.Fatalf("got %d alerts, want 0", len(alerts))
		}
	})

	t.Run("chain spread beyond the window does not fire", func(t *testing.T) {
		// Spacing of 900ms puts the socket well outside a 2s window by
		// the time execve arrives.
		alerts := feedChain(t, baseCfg(),
			chainEvents(5005, 3, []int64{0, 1, 2}, 0, 900*time.Millisecond)...)
		if len(alerts) != 0 {
			t.Fatalf("got %d alerts, want 0", len(alerts))
		}
	})

	t.Run("syscalls split across two processes do not combine", func(t *testing.T) {
		// The tracker is keyed by PID, so this should be impossible —
		// but it is exactly the kind of property worth pinning, because
		// a bug here would produce alerts nobody could reproduce.
		cfg := baseCfg()
		engine, err := NewEngine(cfg, []string{RuleNameReverseShell})
		if err != nil {
			t.Fatal(err)
		}

		engine.Evaluate(makeEvent(events.SysSocket, withPID(6001), withTimestamp(10*time.Millisecond)))
		engine.Evaluate(makeRawEvent(events.Raw{
			SyscallID: uint32(events.SysConnect), TGID: 6001, PID: 6001,
			Family: events.AFInet, Daddr: 0x0100007f, Dport: 0x5c11,
			Timestamp: uint64(20 * time.Millisecond),
		}))
		engine.Evaluate(makeEvent(events.SysDup2, withPID(6002), withTimestamp(30*time.Millisecond), withArgs(3, 0, 0)))
		engine.Evaluate(makeEvent(events.SysDup2, withPID(6002), withTimestamp(40*time.Millisecond), withArgs(3, 1, 0)))

		alerts := engine.Evaluate(makeEvent(events.SysExecve, withPID(6002),
			withTimestamp(50*time.Millisecond), withPath("/bin/sh")))

		if len(alerts) != 0 {
			t.Fatalf("history leaked between processes: got %d alerts", len(alerts))
		}
	})
}

func TestReverseShellDup3IsEquivalent(t *testing.T) {
	// arm64 has no dup2 syscall; glibc's dup2() becomes dup3(). If the rule
	// treated them differently it would be dead on every ARM host.
	cfg := DefaultConfig()
	cfg.SelfPID = 0
	cfg.Stat = statAlways(0o755)

	pid := uint32(5100)
	evs := []events.Event{
		makeEvent(events.SysSocket, withPID(pid), withTimestamp(10*time.Millisecond)),
		makeRawEvent(events.Raw{
			SyscallID: uint32(events.SysSocket), TGID: pid, PID: pid,
			Flags: events.FlagSysExit, Ret: 3, Timestamp: uint64(15 * time.Millisecond),
		}),
		makeRawEvent(events.Raw{
			SyscallID: uint32(events.SysConnect), TGID: pid, PID: pid,
			Family: events.AFInet, Daddr: 0x0100007f, Dport: 0x5c11,
			Timestamp: uint64(20 * time.Millisecond),
		}),
		makeEvent(events.SysDup3, withPID(pid), withTimestamp(30*time.Millisecond), withArgs(3, 0, 0)),
		makeEvent(events.SysDup3, withPID(pid), withTimestamp(40*time.Millisecond), withArgs(3, 1, 0)),
		makeEvent(events.SysExecve, withPID(pid), withTimestamp(50*time.Millisecond), withPath("/bin/sh")),
	}

	if alerts := feedChain(t, cfg, evs...); len(alerts) != 1 {
		t.Fatalf("dup3 chain produced %d alerts, want 1", len(alerts))
	}
}

func TestReverseShellIgnoreLoopback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SelfPID = 0
	cfg.Stat = statAlways(0o755)
	cfg.IgnoreLoopback = true

	alerts := feedChain(t, cfg, chainEvents(5200, 3, []int64{0, 1, 2}, 0, 10*time.Millisecond)...)

	if len(alerts) != 0 {
		t.Fatalf("--ignore-loopback did not suppress a 127.0.0.1 chain: got %d alerts", len(alerts))
	}
}
