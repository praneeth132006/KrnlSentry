package detect

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/praneeth132006/KrnlSentry/events"
)

func TestPrivilegeEscalationRule(t *testing.T) {
	tests := []struct {
		name        string
		event       events.Event
		wantAlert   bool
		wantMitre   string
		wantSummary string
	}{
		{
			name:      "setuid(0) from unprivileged user alerts",
			event:     makeEvent(events.SysSetuid, withUID(1000), withArgs(0, 0, 0)),
			wantAlert: true,
			wantMitre: "T1548",
		},
		{
			// The single most important negative case. Every daemon
			// that drops privileges at startup calls setuid as root.
			// Alerting on those buries the real signal within seconds
			// of the tool starting, and is how a detection gets muted.
			name:      "setuid(0) from root does not alert",
			event:     makeEvent(events.SysSetuid, withUID(0), withArgs(0, 0, 0)),
			wantAlert: false,
		},
		{
			name:      "setuid to a non-root uid does not alert",
			event:     makeEvent(events.SysSetuid, withUID(1000), withArgs(1001, 0, 0)),
			wantAlert: false,
		},
		{
			// setresuid(0,0,0) is what real payloads use, because it
			// leaves no saved uid to drop back to.
			name:      "setresuid(0,0,0) alerts",
			event:     makeEvent(events.SysSetresuid, withUID(1000), withArgs(0, 0, 0)),
			wantAlert: true,
			wantMitre: "T1548",
		},
		{
			name:      "setresuid requesting root for euid only alerts",
			event:     makeEvent(events.SysSetresuid, withUID(1000), withArgs(-1, 0, -1)),
			wantAlert: true,
			wantMitre: "T1548",
		},
		{
			// (uid_t)-1 means "leave unchanged". If the sentinel were
			// mishandled this call would look like an escalation, and
			// setresuid(-1,-1,-1) is common enough that the rule would
			// be unusable.
			name:      "setresuid with all-unchanged sentinels does not alert",
			event:     makeEvent(events.SysSetresuid, withUID(1000), withArgs(-1, -1, -1)),
			wantAlert: false,
		},
		{
			name:      "setgid(0) from unprivileged user alerts",
			event:     makeEvent(events.SysSetgid, withUID(1000), withArgs(0, 0, 0)),
			wantAlert: true,
			wantMitre: "T1548",
		},
		{
			name:      "setresgid(0,0,0) alerts",
			event:     makeEvent(events.SysSetresgid, withUID(1000), withArgs(0, 0, 0)),
			wantAlert: true,
			wantMitre: "T1548",
		},
		{
			name:      "capset from unprivileged user alerts",
			event:     makeEvent(events.SysCapset, withUID(1000)),
			wantAlert: true,
			wantMitre: "T1548",
		},
		{
			// Privileged daemons drop capabilities at startup
			// constantly; without this gate the rule is pure noise.
			name:      "capset from root does not alert",
			event:     makeEvent(events.SysCapset, withUID(0)),
			wantAlert: false,
		},
		{
			name:      "unrelated syscall does not alert",
			event:     makeEvent(events.SysOpenat, withUID(1000), withPath("/tmp/x")),
			wantAlert: false,
		},
		{
			// Exit probes carry clobbered registers; judging them
			// would mean judging garbage.
			name: "exit event does not alert",
			event: makeRawEvent(events.Raw{
				SyscallID: uint32(events.SysSetuid),
				UID:       1000,
				Flags:     events.FlagSysExit,
			}),
			wantAlert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alert := evalPrivilegeEscalation(testContext(tt.event))

			if tt.wantAlert && alert == nil {
				t.Fatal("expected an alert, got none")
			}
			if !tt.wantAlert {
				if alert != nil {
					t.Fatalf("unexpected alert: %s", alert.Description)
				}
				return
			}

			if alert.MitreID != tt.wantMitre {
				t.Errorf("MitreID = %q, want %q", alert.MitreID, tt.wantMitre)
			}
			if alert.Severity != SeverityHigh {
				t.Errorf("Severity = %v, want HIGH", alert.Severity)
			}
			if alert.Rule != RuleNamePrivilegeEscalation {
				t.Errorf("Rule = %q, want %q", alert.Rule, RuleNamePrivilegeEscalation)
			}
			if alert.Description == "" {
				t.Error("Description is empty; alerts must be readable on their own")
			}
		})
	}
}

func TestSuidExecRule(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		uid       uint32
		mode      fs.FileMode
		stat      StatFunc
		wantAlert bool
		wantBits  string
	}{
		{
			name:      "non-root executing setuid binary alerts",
			path:      "/usr/bin/passwd",
			uid:       1000,
			mode:      0o755 | os.ModeSetuid,
			wantAlert: true,
			wantBits:  "setuid",
		},
		{
			name:      "setgid binary alerts",
			path:      "/usr/bin/wall",
			uid:       1000,
			mode:      0o755 | os.ModeSetgid,
			wantAlert: true,
			wantBits:  "setgid",
		},
		{
			name:      "both bits are reported together",
			path:      "/usr/bin/weird",
			uid:       1000,
			mode:      0o755 | os.ModeSetuid | os.ModeSetgid,
			wantAlert: true,
			wantBits:  "setuid,setgid",
		},
		{
			name:      "ordinary binary does not alert",
			path:      "/bin/ls",
			uid:       1000,
			mode:      0o755,
			wantAlert: false,
		},
		{
			name:      "root executing setuid binary does not alert",
			path:      "/usr/bin/passwd",
			uid:       0,
			mode:      0o755 | os.ModeSetuid,
			wantAlert: false,
		},
		{
			// Resolving a relative path needs the process's cwd, and
			// by the time we could read it the exec has already
			// replaced the image. Guessing produces confidently wrong
			// alerts, so the rule stays silent.
			name:      "relative path is skipped rather than guessed",
			path:      "./payload",
			uid:       1000,
			mode:      0o755 | os.ModeSetuid,
			wantAlert: false,
		},
		{
			// The binary was replaced or unlinked between the execve
			// and our stat. Not an alert, and not an error either.
			name:      "missing binary does not alert",
			path:      "/tmp/gone",
			uid:       1000,
			stat:      statMissing(),
			wantAlert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := makeEvent(events.SysExecve, withUID(tt.uid), withPath(tt.path))

			ctx := testContext(ev, func(c *Config) {
				if tt.stat != nil {
					c.Stat = tt.stat
				} else {
					c.Stat = statAlways(tt.mode)
				}
			})

			alert := evalPrivilegeEscalation(ctx)

			if !tt.wantAlert {
				if alert != nil {
					t.Fatalf("unexpected alert: %s", alert.Description)
				}
				return
			}

			if alert == nil {
				t.Fatal("expected an alert, got none")
			}

			if alert.MitreID != "T1548.001" {
				t.Errorf("MitreID = %q, want T1548.001", alert.MitreID)
			}
			if got := alert.Args["suid_bits"]; got != tt.wantBits {
				t.Errorf("args[suid_bits] = %q, want %q", got, tt.wantBits)
			}
			if !strings.Contains(alert.Description, tt.path) {
				t.Errorf("description %q does not name the executed path", alert.Description)
			}
		})
	}
}
