package detect

import (
	"testing"

	"github.com/praneeth132006/KrnlSentry/events"
)

func TestSensitiveFileAccessRule(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantAlert bool
		wantSev   Severity
		wantMitre string
	}{
		{
			name:      "/etc/shadow is HIGH",
			path:      "/etc/shadow",
			wantAlert: true,
			wantSev:   SeverityHigh,
			wantMitre: "T1003.008",
		},
		{
			// The backup file holds the same hashes. Omitting it
			// would leave an obvious one-character bypass.
			name:      "/etc/shadow- backup is HIGH",
			path:      "/etc/shadow-",
			wantAlert: true,
			wantSev:   SeverityHigh,
			wantMitre: "T1003.008",
		},
		{
			name:      "/etc/sudoers is MEDIUM",
			path:      "/etc/sudoers",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552",
		},
		{
			name:      "sudoers.d fragment is MEDIUM",
			path:      "/etc/sudoers.d/90-cloud-init",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552",
		},
		{
			// The directory itself is not a policy fragment.
			name:      "sudoers.d directory itself does not alert",
			path:      "/etc/sudoers.d/",
			wantAlert: false,
		},
		{
			name:      "/proc/<pid>/mem is HIGH",
			path:      "/proc/1234/mem",
			wantAlert: true,
			wantSev:   SeverityHigh,
			wantMitre: "T1003.007",
		},
		{
			name:      "/proc/<pid>/maps is MEDIUM",
			path:      "/proc/1234/maps",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1003.007",
		},
		{
			// path.Match's * does not cross a slash, which is
			// exactly what keeps this from matching.
			name:      "/proc/<pid>/task/<tid>/mem does not match the single-segment glob",
			path:      "/proc/1234/task/5/mem",
			wantAlert: false,
		},
		{
			// Home directories live at unpredictable paths, so these
			// patterns must match at any depth.
			name:      "SSH private key under any home directory",
			path:      "/home/alice/.ssh/id_rsa",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552.004",
		},
		{
			name:      "ed25519 key is covered, not just RSA",
			path:      "/root/.ssh/id_ed25519",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552.004",
		},
		{
			name:      "AWS credentials",
			path:      "/home/bob/.aws/credentials",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552.001",
		},
		{
			name:      "kubeconfig",
			path:      "/home/bob/.kube/config",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552.001",
		},
		{
			// KNOWN FALSE POSITIVE, pinned deliberately.
			//
			// "id_rsa" is a prefix of "id_rsa.pub", so reading the
			// *public* key alerts too. The spec asks for a
			// "~/.ssh/id_rsa*" glob, which has exactly this
			// behaviour, and excluding .pub would then miss
			// "id_rsa.old" and "id_rsa.bak" — files that do contain
			// key material. Over-matching a harmless public key is
			// the better failure, and this test exists so the
			// behaviour is a recorded decision rather than a
			// surprise. Listed in the README's limitations.
			name:      "SSH public key also alerts (known, accepted false positive)",
			path:      "/home/alice/.ssh/id_rsa.pub",
			wantAlert: true,
			wantSev:   SeverityMedium,
			wantMitre: "T1552.004",
		},
		{
			name:      "ordinary file does not alert",
			path:      "/home/alice/notes.txt",
			wantAlert: false,
		},
		{
			name:      "/etc/passwd is not on the list",
			path:      "/etc/passwd",
			wantAlert: false,
		},
		{
			// Lexical normalisation closes the trivial spellings.
			// It cannot close symlinks — that limitation is stated
			// in the rule's own documentation and the README.
			name:      "redundant separators are normalised",
			path:      "/etc//./shadow",
			wantAlert: true,
			wantSev:   SeverityHigh,
			wantMitre: "T1003.008",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := makeEvent(events.SysOpenat, withPath(tt.path))

			alert := evalSensitiveFileAccess(testContext(ev))

			if !tt.wantAlert {
				if alert != nil {
					t.Fatalf("unexpected alert for %q: %s", tt.path, alert.Description)
				}
				return
			}

			if alert == nil {
				t.Fatalf("expected an alert for %q, got none", tt.path)
			}
			if alert.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", alert.Severity, tt.wantSev)
			}
			if alert.MitreID != tt.wantMitre {
				t.Errorf("MitreID = %q, want %q", alert.MitreID, tt.wantMitre)
			}
			if alert.Args["matched_pattern"] == "" {
				t.Error("matched_pattern is not recorded; triage needs to know which rule entry hit")
			}
		})
	}
}

func TestSensitiveFileOnlyMatchesOpenat(t *testing.T) {
	// The path field is populated on execve too. Matching it there would
	// report "opened /etc/shadow" for a process that executed something
	// entirely different.
	ev := makeEvent(events.SysExecve, withPath("/etc/shadow"))

	if alert := evalSensitiveFileAccess(testContext(ev)); alert != nil {
		t.Fatalf("execve of a watched path produced a file-access alert: %s", alert.Description)
	}
}

func TestSensitiveFileSelfProcHandling(t *testing.T) {
	// Allocators, sanitizers and profilers all read their own maps. The
	// alert is still raised by default, but it is labelled so a triager can
	// dismiss it at a glance.
	ev := makeEvent(events.SysOpenat, withPID(4321), withPath("/proc/self/maps"))

	alert := evalSensitiveFileAccess(testContext(ev))
	if alert == nil {
		t.Fatal("expected an alert for /proc/self/maps by default")
	}
	if alert.Args["target_self"] != "true" {
		t.Error("self-access was not labelled; triage cannot distinguish it from cross-process reads")
	}

	// With the flag set it is suppressed entirely.
	suppressed := evalSensitiveFileAccess(testContext(ev, func(c *Config) {
		c.IgnoreSelfProc = true
	}))
	if suppressed != nil {
		t.Fatalf("--ignore-self-proc did not suppress the alert: %s", suppressed.Description)
	}

	// Numeric self-reference must be recognised as well as the "self" link,
	// since a process can open /proc/<its own pid>/maps directly.
	numeric := makeEvent(events.SysOpenat, withPID(4321), withPath("/proc/4321/maps"))
	if a := evalSensitiveFileAccess(testContext(numeric, func(c *Config) {
		c.IgnoreSelfProc = true
	})); a != nil {
		t.Fatalf("numeric self-reference was not recognised: %s", a.Description)
	}
}
