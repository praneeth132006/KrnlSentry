package detect

import (
	"testing"

	"github.com/praneeth132006/KrnlSentry/events"
)

func TestPtraceInjectionRule(t *testing.T) {
	tests := []struct {
		name      string
		request   int64
		comm      string
		targetPID int64
		wantAlert bool
	}{
		{
			name:      "PTRACE_ATTACH from unknown process alerts",
			request:   events.PtraceAttach,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: true,
		},
		{
			name:      "PTRACE_SEIZE alerts",
			request:   events.PtraceSeize,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: true,
		},
		{
			name:      "PTRACE_POKETEXT alerts",
			request:   events.PtracePoketext,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: true,
		},
		{
			name:      "PTRACE_SETREGS alerts",
			request:   events.PtraceSetregs,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: true,
		},
		{
			// The arm64 spelling. Without this case the rule would
			// silently never fire on an ARM host — a gap that fails
			// closed and is therefore invisible in testing.
			name:      "PTRACE_SETREGSET alerts (the arm64 spelling)",
			request:   events.PtraceSetregset,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: true,
		},
		{
			// Reads are reconnaissance, not injection. Including
			// them makes the rule noisy enough to be switched off.
			name:      "PTRACE_PEEKDATA does not alert",
			request:   events.PtracePeekdata,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: false,
		},
		{
			name:      "PTRACE_CONT does not alert",
			request:   events.PtraceCont,
			comm:      "injector",
			targetPID: 2222,
			wantAlert: false,
		},
		{
			name:      "gdb is allowlisted",
			request:   events.PtraceAttach,
			comm:      "gdb",
			targetPID: 2222,
			wantAlert: false,
		},
		{
			name:      "strace is allowlisted",
			request:   events.PtraceAttach,
			comm:      "strace",
			targetPID: 2222,
			wantAlert: false,
		},
		{
			// Exact match only. A substring test would exempt
			// anything merely containing "gdb", widening an already
			// weak control for no benefit.
			name:      "a process merely named like gdb is not allowlisted",
			request:   events.PtraceAttach,
			comm:      "notgdbatall",
			targetPID: 2222,
			wantAlert: true,
		},
		{
			// Self-ptrace is an anti-debugging technique, not
			// injection into another process.
			name:      "targeting itself does not alert",
			request:   events.PtraceAttach,
			comm:      "injector",
			targetPID: 1000, // equals the event PID
			wantAlert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := makeEvent(events.SysPtrace,
				withComm(tt.comm),
				withArgs(tt.request, tt.targetPID, 0))

			alert := evalPtraceInjection(testContext(ev))

			if !tt.wantAlert {
				if alert != nil {
					t.Fatalf("unexpected alert: %s", alert.Description)
				}
				return
			}

			if alert == nil {
				t.Fatal("expected an alert, got none")
			}
			if alert.MitreID != "T1055.008" {
				t.Errorf("MitreID = %q, want T1055.008", alert.MitreID)
			}
			if alert.Severity != SeverityHigh {
				t.Errorf("Severity = %v, want HIGH", alert.Severity)
			}
			if alert.Args["action"] == "" {
				t.Error("action is not recorded; the alert should say what the request does")
			}
		})
	}
}

// TestPtraceAllowlistIsConfigurable documents that the allowlist is a knob, not
// a hardcoded policy — and, by extension, that it is trivially bypassed by
// anything that renames itself. See the rule's own comment.
func TestPtraceAllowlistIsConfigurable(t *testing.T) {
	ev := makeEvent(events.SysPtrace,
		withComm("mydebugger"),
		withArgs(events.PtraceAttach, 2222, 0))

	if alert := evalPtraceInjection(testContext(ev)); alert == nil {
		t.Fatal("expected an alert with the default allowlist")
	}

	ctx := testContext(ev, func(c *Config) {
		c.DebuggerComms = append(c.DebuggerComms, "mydebugger")
	})

	if alert := evalPtraceInjection(ctx); alert != nil {
		t.Fatalf("adding to the allowlist did not suppress: %s", alert.Description)
	}
}
