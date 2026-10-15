package detect

import (
	"testing"
	"time"
)

func TestDedupFoldsRepeatsWithinWindow(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.DedupWindow = 5 * time.Second })

	var got []*Alert
	for i := 0; i < 100; i++ {
		got = append(got, feed(e, cat.open(time.Duration(i)*10*time.Millisecond, "/etc/shadow"))...)
	}

	if len(got) != 1 {
		t.Fatalf("100 identical opens in 1s produced %d alerts, want 1", len(got))
	}
	if got[0].Suppressed != 0 {
		t.Errorf("first emission reports %d suppressed, want 0", got[0].Suppressed)
	}
	if s := e.Stats().Suppressed; s != 99 {
		t.Errorf("Stats().Suppressed = %d, want 99", s)
	}

	// After the window the finding resurfaces, carrying the fold count.
	again := feed(e, cat.open(6*time.Second, "/etc/shadow"))
	if len(again) != 1 {
		t.Fatalf("repeat after the window produced %d alerts, want 1", len(again))
	}
	if again[0].Suppressed != 99 {
		t.Errorf("resurfaced alert reports %d suppressed, want 99", again[0].Suppressed)
	}
}

// Different paths, processes or rules are different findings and must never
// fold into each other.
func TestDedupKeepsDistinctFindings(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.DedupWindow = time.Minute })

	got := feed(e,
		cat.open(0, "/etc/shadow"),
		cat.open(1, "/etc/gshadow"),
		exploit.open(2, "/etc/shadow"),
		cat.setuid(3, 0),
	)

	if n := len(byRule(got, RuleNameSensitiveFile)) + len(byRule(got, RuleNamePrivilegeEscalation)); n != 4 {
		t.Fatalf("got %d alerts from four distinct findings, want 4: %v", n, ruleNames(got))
	}
}

func TestDedupDisabled(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.DedupWindow = 0 })

	got := feed(e, cat.open(0, "/etc/shadow"), cat.open(1, "/etc/shadow"))
	if len(got) != 2 {
		t.Fatalf("dedup disabled but got %d alerts, want 2", len(got))
	}
}

// Folding must not starve the correlator: a story should still learn the
// tactic from alerts the deduplicator swallowed.
func TestDedupDoesNotHideEvidenceFromStorylines(t *testing.T) {
	e := storyEngine(t, func(c *Config) {
		c.DedupWindow = time.Minute
		c.Storyline.Threshold = 2
	})

	feed(e, cat.open(0, "/etc/shadow"))
	feed(e, cat.open(time.Millisecond, "/etc/shadow")) // folded

	chains := byRule(feed(e, exploit.setuid(time.Second, 0)), RuleNameAttackChain)
	if len(chains) != 1 {
		t.Fatal("expected an attack chain")
	}
	if got := chains[0].Args["alert_count"]; got != "3" {
		t.Errorf("alert_count = %s, want 3 (folded alerts still count as evidence)", got)
	}
}
