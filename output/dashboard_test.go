package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/detect"
)

// renderAt builds a dashboard with a fixed geometry and clock, so every
// assertion below is about layout and content rather than about the terminal
// the test happens to run in.
func renderAt(t *testing.T, color bool, opts func(*DashboardOptions), alerts ...*detect.Alert) (*Dashboard, string) {
	t.Helper()

	o := DashboardOptions{
		Version:   "v1.2.3",
		Mode:      "live",
		Scope:     "system-wide",
		AlertPath: "/var/log/krnlsentry.jsonl",
		Rules: []string{
			"privilege-escalation", "sensitive-file-access",
			"process-injection", "reverse-shell", "attack-chain",
		},
		Color:   color,
		Width:   110,
		Height:  44,
		Metrics: func() Metrics { return Metrics{Observed: 12045, TrackedProcs: 31, Progress: -1} },
		Now:     func() time.Time { return time.Unix(1700000000, 0) },
	}
	if opts != nil {
		opts(&o)
	}

	d := NewDashboard(&bytes.Buffer{}, o)

	for _, a := range alerts {
		if err := d.Write(a); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	return d, d.Render()
}

func alert(sev detect.Severity, rule, comm string, pid uint32, mitre, desc string) *detect.Alert {
	return &detect.Alert{
		Timestamp:      time.Date(2026, 10, 5, 11, 0, 33, 731000000, time.UTC),
		PID:            pid,
		Comm:           comm,
		Severity:       sev,
		Rule:           rule,
		MitreID:        mitre,
		MitreTechnique: "technique",
		Description:    desc,
	}
}

func TestDashboardEmptyFrameStatesWhatIsArmed(t *testing.T) {
	_, frame := renderAt(t, false, nil)

	// An idle security tool is ambiguous — nothing happening and nothing
	// watching look identical — so the empty frame has to answer "what is
	// running, and where does output go?" on its own.
	for _, want := range []string{
		"KrnlSentry v1.2.3", "LIVE", "system-wide",
		"reverse-shell", "attack-chain", "process-injection",
		"CRITICAL", "LOW",
		"no alerts yet",
		"/var/log/krnlsentry.jsonl",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("empty frame missing %q:\n%s", want, frame)
		}
	}
}

func TestDashboardCountsAlerts(t *testing.T) {
	d, frame := renderAt(t, false, nil,
		alert(detect.SeverityHigh, "privilege-escalation", "exploit", 4140, "T1548", "setuid(0)"),
		alert(detect.SeverityHigh, "privilege-escalation", "exploit", 4140, "T1548", "setgid(0)"),
		alert(detect.SeverityCritical, "reverse-shell", "python3", 4150, "T1059", "reverse shell to 10.13.37.9:4444"),
	)

	if d.total != 3 {
		t.Errorf("total = %d, want 3", d.total)
	}
	if got := d.bySeverity[detect.SeverityHigh]; got != 2 {
		t.Errorf("HIGH = %d, want 2", got)
	}
	if got := d.byRule["privilege-escalation"]; got != 2 {
		t.Errorf("privilege-escalation = %d, want 2", got)
	}
	if got := d.byProcess[procKey{Comm: "exploit", PID: 4140}]; got != 2 {
		t.Errorf("exploit[4140] = %d, want 2", got)
	}

	// Tactics are rolled up from the technique, not stored on the alert, so
	// this also pins that the dashboard asks detect/ rather than guessing.
	if got := d.byTactic[detect.TacticPrivEsc.Name]; got != 2 {
		t.Errorf("Privilege Escalation tactic = %d, want 2", got)
	}

	if !strings.Contains(frame, "exploit[4140]") {
		t.Errorf("top processes missing the repeat offender:\n%s", frame)
	}
	if !strings.Contains(frame, "3 total") {
		t.Errorf("alert feed missing its total:\n%s", frame)
	}
}

func TestDashboardFeedIsNewestFirst(t *testing.T) {
	_, frame := renderAt(t, false, nil,
		alert(detect.SeverityLow, "sensitive-file-access", "cat", 1, "T1552", "FIRST-ALERT"),
		alert(detect.SeverityLow, "sensitive-file-access", "cat", 2, "T1552", "SECOND-ALERT"),
	)

	first := strings.Index(frame, "FIRST-ALERT")
	second := strings.Index(frame, "SECOND-ALERT")

	if first < 0 || second < 0 {
		t.Fatalf("both alerts should be shown:\n%s", frame)
	}
	if second > first {
		t.Errorf("feed should be newest first; got FIRST at %d before SECOND at %d", first, second)
	}
}

func TestDashboardShowsAttackChainTimeline(t *testing.T) {
	chain := alert(detect.SeverityCritical, detect.RuleNameAttackChain, "python3", 4150, "T1059",
		"Multi-stage attack in the process tree of bash[4100]")
	chain.Story = []detect.StoryStep{
		{OffsetMS: 0, PID: 4120, Comm: "cat", Tactic: "Credential Access", Summary: "openat /home/dev/.aws/credentials"},
		{OffsetMS: 18041, PID: 4150, Comm: "python3", Tactic: "Execution", Summary: "reverse shell to 10.13.37.9:4444"},
	}

	_, frame := renderAt(t, false, func(o *DashboardOptions) {
		o.Metrics = func() Metrics { return Metrics{Storylines: 1, AttackChains: 2, Progress: -1} }
	}, chain)

	for _, want := range []string{
		"chains raised 2",
		"+0ms", "cat[4120]", "Credential Access",
		"+18041ms", "python3[4150]",
		"└─",
	} {
		if !strings.Contains(frame, want) {
			t.Errorf("chain timeline missing %q:\n%s", want, frame)
		}
	}
}

func TestDashboardMinSeverityFiltersFeedNotTotals(t *testing.T) {
	_, frame := renderAt(t, false, func(o *DashboardOptions) {
		o.MinSeverity = detect.SeverityHigh
	},
		alert(detect.SeverityMedium, "sensitive-file-access", "cat", 4120, "T1552", "QUIET-ALERT"),
		alert(detect.SeverityCritical, "reverse-shell", "python3", 4150, "T1059", "LOUD-ALERT"),
	)

	if strings.Contains(frame, "QUIET-ALERT") {
		t.Errorf("feed should hide alerts below --min-severity:\n%s", frame)
	}
	if !strings.Contains(frame, "LOUD-ALERT") {
		t.Errorf("feed should show alerts at or above --min-severity:\n%s", frame)
	}

	// The headline count must still be the truth about the run.
	if !strings.Contains(frame, "2 total") {
		t.Errorf("totals must not be filtered by --min-severity:\n%s", frame)
	}
}

func TestDashboardSurfacesDrops(t *testing.T) {
	_, frame := renderAt(t, false, func(o *DashboardOptions) {
		o.Metrics = func() Metrics {
			return Metrics{Observed: 10, QueueDropped: 7, KernelDrops: 5, WriteErrors: 1, Progress: -1}
		}
	})

	// A tool that silently discarded events looks exactly like one that saw
	// nothing suspicious, so the drop total is never hidden or rolled up.
	if !strings.Contains(frame, "drops 12") {
		t.Errorf("frame should show 12 combined drops:\n%s", frame)
	}
	if !strings.Contains(frame, "write errors 1") {
		t.Errorf("frame should show write errors:\n%s", frame)
	}
}

func TestDashboardReplayProgress(t *testing.T) {
	_, frame := renderAt(t, false, func(o *DashboardOptions) {
		o.Mode, o.Source = "replay", "testdata/captures/intrusion.jsonl"
		o.Metrics = func() Metrics { return Metrics{Progress: 0.5} }
	})

	if !strings.Contains(frame, "REPLAY") || !strings.Contains(frame, "intrusion.jsonl") {
		t.Errorf("replay header missing its source:\n%s", frame)
	}
	if !strings.Contains(frame, "50%") {
		t.Errorf("replay progress missing:\n%s", frame)
	}
}

// TestDashboardLinesFitWidth is the regression test for the alignment bug class:
// a cell padded by counting bytes rather than printable columns skews every
// panel to its right, and the failure is invisible without colour enabled.
func TestDashboardLinesFitWidth(t *testing.T) {
	chain := alert(detect.SeverityCritical, detect.RuleNameAttackChain, "python3", 4150,
		"T1552.001,T1055.008,T1548,T1059",
		strings.Repeat("a very long multi-stage attack description ", 8))
	chain.Story = []detect.StoryStep{
		{OffsetMS: 18041, PID: 4150, Comm: "a-process-with-a-long-name", Tactic: "Execution + Command and Control", Summary: strings.Repeat("long/path/", 20)},
	}

	for _, color := range []bool{false, true} {
		for _, width := range []int{80, 110, 160} {
			_, frame := renderAt(t, color, func(o *DashboardOptions) {
				o.Width = width
			}, chain,
				alert(detect.SeverityHigh, "privilege-escalation", "exploit", 4140, "T1548", strings.Repeat("x", 300)))

			for i, line := range strings.Split(frame, "\n") {
				if n := visibleLen(line); n > width {
					t.Errorf("color=%v width=%d: line %d is %d columns wide:\n%s",
						color, width, i, n, line)
				}
			}
		}
	}
}

func TestDashboardPaintIsIdempotentAndRepaints(t *testing.T) {
	var buf bytes.Buffer

	d := NewDashboard(&buf, DashboardOptions{Width: 100, Height: 40})

	if err := d.Paint(); err != nil {
		t.Fatalf("Paint: %v", err)
	}
	first := buf.Len()

	if err := d.Paint(); err != nil {
		t.Fatalf("Paint: %v", err)
	}

	if buf.Len() <= first {
		t.Error("second paint wrote nothing")
	}

	// Homing the cursor and erasing only what the new frame does not cover
	// is what keeps the repaint flicker-free; clearing first would blank
	// the terminal on every frame.
	if !strings.Contains(buf.String(), ansiHome) {
		t.Error("paint should home the cursor")
	}
	if !strings.Contains(buf.String(), ansiClearBelow) {
		t.Error("paint should erase below the frame")
	}
}

func TestDashboardStartStopLeavesFinalFrame(t *testing.T) {
	var buf bytes.Buffer

	d := NewDashboard(&buf, DashboardOptions{
		Width: 100, Height: 40, Refresh: time.Millisecond,
	})

	d.Start()
	_ = d.Write(alert(detect.SeverityCritical, "reverse-shell", "python3", 4150, "T1059", "PERSISTED-ALERT"))

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close must be safe to call twice: the agent closes the dashboard from
	// a defer, and an error path may have closed it already.
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// The run's totals have to survive the tool exiting — an operator
	// reading the summary still wants the numbers above it.
	if !strings.Contains(buf.String(), "PERSISTED-ALERT") {
		t.Error("final frame should still be on screen after Close")
	}
}

func TestDashboardRecentIsBounded(t *testing.T) {
	d, _ := renderAt(t, false, nil)

	for i := 0; i < recentCap*3; i++ {
		_ = d.Write(alert(detect.SeverityLow, "sensitive-file-access", "cat", uint32(i), "T1552", "x"))
	}

	if len(d.recent) != recentCap {
		t.Errorf("recent = %d entries, want the cap of %d", len(d.recent), recentCap)
	}
	if d.total != uint64(recentCap*3) {
		t.Errorf("total = %d, want %d — the cap bounds memory, not the count", d.total, recentCap*3)
	}
}

func TestVisibleLenSkipsEscapes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"plain", 5},
		{ansiRed + "red" + ansiReset, 3},
		{ansiBgRed + ansiWhite + ansiBold + " CRITICAL " + ansiReset, 10},
		{"\033[?25lhi", 2},
		{"\033(Bhi", 2},
		{"", 0},
	}

	for _, c := range cases {
		if got := visibleLen(c.in); got != c.want {
			t.Errorf("visibleLen(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestPadAndTruncate(t *testing.T) {
	if got := padVisible(ansiRed+"ab"+ansiReset, 5); visibleLen(got) != 5 {
		t.Errorf("padVisible produced %d visible columns, want 5", visibleLen(got))
	}
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Errorf("truncate = %q, want %q", got, "abc…")
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Errorf("truncate should leave short strings alone, got %q", got)
	}
	if got := truncate("abc", 0); got != "" {
		t.Errorf("truncate to zero = %q, want empty", got)
	}
}

func TestFormatHelpers(t *testing.T) {
	if got := formatCount(1234567); got != "1 234 567" {
		t.Errorf("formatCount = %q", got)
	}
	if got := formatCount(42); got != "42" {
		t.Errorf("formatCount = %q", got)
	}
	if got := formatDuration(3*time.Hour + 4*time.Minute + 5*time.Second); got != "3:04:05" {
		t.Errorf("formatDuration = %q", got)
	}
	if got := formatDuration(65 * time.Second); got != "01:05" {
		t.Errorf("formatDuration = %q", got)
	}

	// A non-zero count must never render as an empty bar: "0" and "1 in a
	// million" have to be distinguishable at a glance.
	if got := bar(1, 1000000, 20); got == "" {
		t.Error("bar(1, 1000000) rendered empty")
	}
	if got := bar(0, 10, 20); got != "" {
		t.Errorf("bar(0, …) = %q, want empty", got)
	}
	if got := len([]rune(meter(0.5, 10))); got != 10 {
		t.Errorf("meter width = %d, want 10", got)
	}
}

func TestDashboardNilAlertIsIgnored(t *testing.T) {
	d, _ := renderAt(t, false, nil)

	if err := d.Write(nil); err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if d.total != 0 {
		t.Errorf("nil alert counted: total = %d", d.total)
	}
}

// The dashboard is a Sink like any other, so the agent can fan alerts out to it
// without knowing what it is.
var _ Sink = (*Dashboard)(nil)

// TestDashboardFitsTerminalHeight is the other half of the alignment contract:
// a frame one line too tall scrolls the terminal, which moves the home position
// the next repaint draws from, and the display then tears itself apart.
func TestDashboardFitsTerminalHeight(t *testing.T) {
	chain := alert(detect.SeverityCritical, detect.RuleNameAttackChain, "python3", 4150, "T1059", "Multi-stage attack")
	for i := 0; i < 24; i++ {
		chain.Story = append(chain.Story, detect.StoryStep{
			OffsetMS: int64(i) * 1000, PID: uint32(4000 + i), Comm: "proc", Tactic: "Execution", Summary: "did something",
		})
	}

	for _, height := range []int{MinUsableHeight, 26, 30, 40, 60} {
		d, _ := renderAt(t, false, func(o *DashboardOptions) { o.Height = height }, chain)

		for i := 0; i < 40; i++ {
			_ = d.Write(alert(detect.SeverityHigh, "privilege-escalation", "exploit", uint32(i), "T1548", "setuid(0)"))
		}

		frame := d.Render()
		if lines := strings.Count(frame, "\n"); lines > height-1 {
			t.Errorf("height %d: frame is %d lines:\n%s", height, lines, frame)
		}

		// Shrinking must never cost the headline numbers.
		for _, want := range []string{"CRITICAL", "RECENT ALERTS", "drops"} {
			if !strings.Contains(frame, want) {
				t.Errorf("height %d: frame dropped %q:\n%s", height, want, frame)
			}
		}
	}
}

// Below MinUsableHeight the frame is allowed to be taller than the terminal,
// but it must still carry the numbers — cutting those to fit would be the one
// trade the display is never allowed to make.
func TestDashboardBelowMinimumHeightKeepsTheTotals(t *testing.T) {
	d, _ := renderAt(t, false, func(o *DashboardOptions) { o.Height = 16 },
		alert(detect.SeverityCritical, "reverse-shell", "python3", 4150, "T1059", "reverse shell"))

	frame := d.Render()

	for _, want := range []string{"KrnlSentry", "alerts 1", "CRITICAL", "RECENT ALERTS"} {
		if !strings.Contains(frame, want) {
			t.Errorf("short terminal dropped %q:\n%s", want, frame)
		}
	}

	// The context panels are what gets shed first.
	if strings.Contains(frame, "TOP PROCESSES") {
		t.Errorf("short terminal should shed the processes panel:\n%s", frame)
	}
}

func TestDashboardTrimmedStoryKeepsItsOpeningAndSaysWhatItCut(t *testing.T) {
	chain := alert(detect.SeverityCritical, detect.RuleNameAttackChain, "python3", 4150, "T1059", "Multi-stage attack")
	chain.Story = []detect.StoryStep{
		{OffsetMS: 0, PID: 1, Comm: "FIRST", Tactic: "Credential Access", Summary: "read creds"},
		{OffsetMS: 1, PID: 2, Comm: "second", Tactic: "Execution", Summary: "ran"},
		{OffsetMS: 2, PID: 3, Comm: "third", Tactic: "Execution", Summary: "ran"},
		{OffsetMS: 3, PID: 4, Comm: "fourth", Tactic: "Execution", Summary: "ran"},
	}

	d := NewDashboard(&bytes.Buffer{}, DashboardOptions{Width: 110, Height: 60, AlertPath: "/var/log/krnlsentry.jsonl"})
	if err := d.Write(chain); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Two rows: one step plus the "more steps" line.
	frame := d.render(layout{storyRows: 2, recentRows: 3, showTactics: true, showProcesses: true})

	if !strings.Contains(frame, "FIRST") {
		t.Errorf("trimmed story lost where the intrusion started:\n%s", frame)
	}
	if !strings.Contains(frame, "3 more step(s)") {
		t.Errorf("trimmed story should account for what it cut:\n%s", frame)
	}
	if !strings.Contains(frame, "/var/log/krnlsentry.jsonl") {
		t.Errorf("trimmed story should point at the full record:\n%s", frame)
	}
}
