package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/detect"
)

func TestConsoleRendersStoryTimeline(t *testing.T) {
	var buf bytes.Buffer
	sink := NewConsoleSink(&buf, false, detect.SeverityLow)

	err := sink.Write(&detect.Alert{
		Timestamp:   time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC),
		PID:         4150,
		Comm:        "python3",
		Severity:    detect.SeverityCritical,
		Rule:        detect.RuleNameAttackChain,
		Description: "Multi-stage attack",
		Story: []detect.StoryStep{
			{OffsetMS: 0, PID: 4120, Comm: "cat", Tactic: "Credential Access", Summary: "openat /etc/shadow"},
			{OffsetMS: 1500, PID: 4150, Comm: "python3", Tactic: "Execution", Summary: "reverse shell to 10.0.0.1:4444"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"├─ +0ms", "cat[4120]", "openat /etc/shadow",
		"└─ +1500ms", "python3[4150]", "reverse shell to 10.0.0.1:4444",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("colour disabled but output contains ANSI escapes")
	}
}

func TestConsoleShowsFoldCount(t *testing.T) {
	var buf bytes.Buffer
	sink := NewConsoleSink(&buf, false, detect.SeverityLow)

	if err := sink.Write(&detect.Alert{Severity: detect.SeverityHigh, Rule: "x", Suppressed: 41}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "+41 identical alert(s) folded") {
		t.Errorf("fold count not shown:\n%s", buf.String())
	}
}
