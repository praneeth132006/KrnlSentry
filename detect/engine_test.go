package detect

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

func TestNewEngineRuleSelection(t *testing.T) {
	cfg := DefaultConfig()

	t.Run("empty selection enables everything", func(t *testing.T) {
		e, err := NewEngine(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Rules()) != len(AllRules()) {
			t.Errorf("enabled %d rules, want all %d", len(e.Rules()), len(AllRules()))
		}
	})

	t.Run("named subset", func(t *testing.T) {
		e, err := NewEngine(cfg, []string{RuleNameReverseShell, RuleNameProcessInjection})
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Rules()) != 2 {
			t.Fatalf("enabled %d rules, want 2", len(e.Rules()))
		}
	})

	t.Run("whitespace is tolerated", func(t *testing.T) {
		if _, err := NewEngine(cfg, []string{"  reverse-shell  "}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// A typo must be fatal, not a warning. Starting up having silently
	// enabled nothing is the worst outcome available: the tool looks
	// healthy and detects nothing.
	t.Run("unknown rule is an error", func(t *testing.T) {
		_, err := NewEngine(cfg, []string{"revshel"})
		if err == nil {
			t.Fatal("expected an error for an unknown rule name")
		}
		if !strings.Contains(err.Error(), "revshel") {
			t.Errorf("error does not name the offending rule: %v", err)
		}
		// The message must also list what is available, or the user has
		// to go read the source to find the right spelling.
		if !strings.Contains(err.Error(), RuleNameReverseShell) {
			t.Errorf("error does not list available rules: %v", err)
		}
	})
}

func TestEngineIgnoresItself(t *testing.T) {
	// The kernel already filters the agent's own events. This is the second
	// guard, so that a regression in the kernel filter cannot reintroduce
	// the log→syscall→log feedback loop.
	cfg := DefaultConfig()
	cfg.SelfPID = 4242
	cfg.Stat = statAlways(0o755)

	engine, err := NewEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	ev := makeEvent(events.SysOpenat, withPID(4242), withPath("/etc/shadow"))

	if alerts := engine.Evaluate(ev); len(alerts) != 0 {
		t.Fatalf("engine alerted on its own event: %d alerts", len(alerts))
	}
}

func TestEngineMultipleRulesCanFire(t *testing.T) {
	// A setuid execve that also completes a reverse-shell chain should
	// produce both alerts — they describe genuinely different findings and
	// collapsing them would lose information.
	cfg := DefaultConfig()
	cfg.SelfPID = 0
	// Note os.ModeSetuid rather than the Unix octal 0o4755: Go's fs.FileMode
	// carries setuid as its own bit (1<<23), not in the permission octal, so
	// 0o4755 would silently be an ordinary file with odd permissions.
	cfg.Stat = statAlways(0o755 | os.ModeSetuid)

	engine, err := NewEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	pid := uint32(7000)
	for _, ev := range []events.Event{
		makeEvent(events.SysSocket, withPID(pid), withUID(1000), withTimestamp(10*time.Millisecond)),
		makeRawEvent(events.Raw{
			SyscallID: uint32(events.SysConnect), TGID: pid, PID: pid, UID: 1000,
			Family: events.AFInet, Daddr: 0x0100007f, Dport: 0x5c11,
			Timestamp: uint64(20 * time.Millisecond),
		}),
		makeEvent(events.SysDup2, withPID(pid), withUID(1000), withTimestamp(30*time.Millisecond), withArgs(3, 0, 0)),
		makeEvent(events.SysDup2, withPID(pid), withUID(1000), withTimestamp(40*time.Millisecond), withArgs(3, 1, 0)),
	} {
		engine.Evaluate(ev)
	}

	final := makeEvent(events.SysExecve, withPID(pid), withUID(1000),
		withTimestamp(50*time.Millisecond), withPath("/bin/sh"))

	alerts := engine.Evaluate(final)

	if len(alerts) != 2 {
		names := make([]string, len(alerts))
		for i, a := range alerts {
			names[i] = a.Rule
		}
		t.Fatalf("got %d alerts (%v), want 2 (privilege-escalation and reverse-shell)", len(alerts), names)
	}
}

// TestAlertJSONContract pins the output field names.
//
// alerts.jsonl is an API: dashboards, SIEM parsers and the run-all.sh smoke
// test all read these keys. Renaming one is a breaking change, so it should
// fail a test rather than quietly break somebody's pipeline.
func TestAlertJSONContract(t *testing.T) {
	ev := makeEvent(events.SysSetuid, withUID(1000), withArgs(0, 0, 0))

	alert := evalPrivilegeEscalation(testContext(ev))
	if alert == nil {
		t.Fatal("expected an alert")
	}

	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("marshalling alert: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshalling alert: %v", err)
	}

	required := []string{
		"timestamp", "pid", "ppid", "comm", "uid",
		"syscall", "args", "mitre_id", "mitre_technique",
		"severity", "description", "rule",
	}

	for _, field := range required {
		if _, ok := decoded[field]; !ok {
			t.Errorf("required field %q missing from alert JSON", field)
		}
	}

	// Severity must serialise as a name, not the underlying integer.
	if got := decoded["severity"]; got != "HIGH" {
		t.Errorf("severity = %v, want \"HIGH\" (a name, not an ordinal)", got)
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, name := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		sev, ok := ParseSeverity(name)
		if !ok {
			t.Errorf("ParseSeverity(%q) failed", name)
			continue
		}
		if sev.String() != name {
			t.Errorf("round trip of %q produced %q", name, sev.String())
		}
	}

	if _, ok := ParseSeverity("BANANA"); ok {
		t.Error("ParseSeverity accepted an invalid severity")
	}
}

// TestSeverityOrdering matters because --min-severity filters with `<`.
func TestSeverityOrdering(t *testing.T) {
	if !(SeverityLow < SeverityMedium && SeverityMedium < SeverityHigh && SeverityHigh < SeverityCritical) {
		t.Fatal("severity constants are not in ascending order; --min-severity filtering would be wrong")
	}
}

func TestRuleNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range AllRules() {
		if seen[r.Name] {
			t.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true

		if r.Eval == nil {
			t.Errorf("rule %q has no Eval function", r.Name)
		}
		if r.Description == "" {
			t.Errorf("rule %q has no description", r.Name)
		}
		if len(r.Techniques) == 0 {
			t.Errorf("rule %q declares no ATT&CK techniques", r.Name)
		}
	}
}
