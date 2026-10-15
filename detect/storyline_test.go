package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

func withPPID(ppid uint32) eventOpt {
	return func(e *events.Event) { e.PPID = ppid }
}

// proc is shorthand for "an event from this process", so scenarios read as a
// process tree rather than as a wall of options.
type proc struct {
	pid, ppid uint32
	comm      string
	uid       uint32
}

func (p proc) opts(at time.Duration) []eventOpt {
	return []eventOpt{withPID(p.pid), withPPID(p.ppid), withComm(p.comm), withUID(p.uid), withTimestamp(at)}
}

func (p proc) exec(at time.Duration, path string) events.Event {
	return makeEvent(events.SysExecve, append(p.opts(at), withPath(path))...)
}

func (p proc) open(at time.Duration, path string) events.Event {
	return makeEvent(events.SysOpenat, append(p.opts(at), withPath(path))...)
}

func (p proc) setuid(at time.Duration, uid int64) events.Event {
	ev := makeEvent(events.SysSetuid, append(p.opts(at), withArgs(uid, 0, 0))...)
	ev.Args["target_uid"] = "0"
	return ev
}

func (p proc) ptrace(at time.Duration, target int64) events.Event {
	ev := makeEvent(events.SysPtrace, append(p.opts(at), withArgs(16, target, 0))...) // PTRACE_ATTACH
	ev.Args["request"] = "PTRACE_ATTACH"
	return ev
}

// revshell returns the full socket → connect → dup2 ×3 → execve chain.
func (p proc) revshell(at time.Duration) []events.Event {
	evs := chainEvents(p.pid, 3, []int64{0, 1, 2}, at, time.Millisecond)
	for i := range evs {
		evs[i].PPID = p.ppid
		evs[i].Comm = p.comm
		evs[i].UID = p.uid
	}
	return evs
}

func storyEngine(t *testing.T, mutate ...func(*Config)) *Engine {
	t.Helper()

	cfg := DefaultConfig()
	cfg.SelfPID = 0
	cfg.Stat = statAlways(0o755)
	cfg.DedupWindow = 0
	for _, m := range mutate {
		m(&cfg)
	}

	e, err := NewEngine(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func feed(e *Engine, evs ...events.Event) []*Alert {
	var out []*Alert
	for _, ev := range evs {
		out = append(out, e.Evaluate(ev)...)
	}
	return out
}

func byRule(alerts []*Alert, rule string) []*Alert {
	var out []*Alert
	for _, a := range alerts {
		if a.Rule == rule {
			out = append(out, a)
		}
	}
	return out
}

var (
	sshd    = proc{pid: 50, ppid: 1, comm: "sshd", uid: 0}
	bash    = proc{pid: 100, ppid: 50, comm: "bash", uid: 1000}
	cat     = proc{pid: 101, ppid: 100, comm: "cat", uid: 1000}
	exploit = proc{pid: 102, ppid: 100, comm: "exploit", uid: 1000}
	python3 = proc{pid: 103, ppid: 100, comm: "python3", uid: 1000}
)

// TestStorylineStitchesAProcessTree is the headline scenario: three sibling
// processes under one login shell each trip a different rule. Individually
// they are a MEDIUM, a HIGH and a CRITICAL in a queue; together they are one
// intrusion, and the correlator must say so exactly once.
func TestStorylineStitchesAProcessTree(t *testing.T) {
	e := storyEngine(t)

	var alerts []*Alert
	alerts = append(alerts, feed(e,
		sshd.exec(0, "/usr/sbin/sshd"),
		bash.exec(time.Second, "/bin/bash"),
		cat.open(2*time.Second, "/etc/shadow"),
		exploit.setuid(3*time.Second, 0),
	)...)
	alerts = append(alerts, feed(e, python3.revshell(4*time.Second)...)...)

	chains := byRule(alerts, RuleNameAttackChain)
	if len(chains) != 1 {
		t.Fatalf("got %d attack-chain alerts, want 1 (alerts: %v)", len(chains), ruleNames(alerts))
	}
	chain := chains[0]

	if chain.Severity != SeverityCritical {
		t.Errorf("attack-chain severity = %v, want CRITICAL", chain.Severity)
	}

	wantTactics := "Credential Access → Privilege Escalation → Execution → Command and Control"
	if got := chain.Args["tactics"]; got != wantTactics {
		t.Errorf("tactics = %q, want %q", got, wantTactics)
	}

	if got := chain.Args["root"]; got != "bash[100]" {
		t.Errorf("root = %q, want bash[100] — the walk must stop below sshd", got)
	}

	if len(chain.Story) != 3 {
		t.Fatalf("story has %d steps, want 3: %+v", len(chain.Story), chain.Story)
	}
	if chain.Story[0].Summary != "openat /etc/shadow" || chain.Story[0].OffsetMS != 0 {
		t.Errorf("first step = %+v, want the shadow read at offset 0", chain.Story[0])
	}
	if !strings.HasPrefix(chain.Story[2].Summary, "reverse shell to 127.0.0.1:") {
		t.Errorf("last step summary = %q", chain.Story[2].Summary)
	}

	// Every contributing alert carries the same storyline id, which is
	// what lets a SIEM pivot from any one of them to the rest.
	for _, a := range alerts {
		if a.Storyline != chain.Storyline {
			t.Errorf("%s alert has storyline %q, want %q", a.Rule, a.Storyline, chain.Storyline)
		}
	}
}

// TestStorylineSessionBoundaries checks that two SSH sessions do not merge
// just because both descend from sshd and init.
func TestStorylineSessionBoundaries(t *testing.T) {
	e := storyEngine(t)

	otherSSHD := proc{pid: 60, ppid: 1, comm: "sshd"}
	otherBash := proc{pid: 200, ppid: 60, comm: "bash", uid: 1001}
	otherCat := proc{pid: 201, ppid: 200, comm: "cat", uid: 1001}

	a := feed(e,
		sshd.exec(0, "/usr/sbin/sshd"),
		otherSSHD.exec(0, "/usr/sbin/sshd"),
		cat.open(time.Second, "/etc/shadow"),
		otherCat.open(time.Second, "/etc/shadow"),
		exploit.setuid(2*time.Second, 0),
		otherBash.ptrace(2*time.Second, 1),
	)

	if chains := byRule(a, RuleNameAttackChain); len(chains) != 0 {
		t.Fatalf("two sessions with two tactics each were merged into an attack chain: %s", chains[0].Description)
	}

	ids := map[string]bool{}
	for _, al := range a {
		ids[al.Storyline] = true
	}
	if len(ids) != 2 {
		t.Errorf("got %d storylines, want 2 (one per session)", len(ids))
	}
}

// TestStorylineDiversityNotVolume: one tactic, however loud, is not a chain.
func TestStorylineDiversityNotVolume(t *testing.T) {
	e := storyEngine(t)

	var evs []events.Event
	for i := 0; i < 50; i++ {
		evs = append(evs, cat.open(time.Duration(i)*time.Millisecond, "/etc/shadow"))
	}

	if chains := byRule(feed(e, evs...), RuleNameAttackChain); len(chains) != 0 {
		t.Fatal("fifty reads of one file raised an attack chain")
	}
}

// TestStorylineReraisesOnNewTactic: a story already over the threshold that
// gains a further tactic is reported again with the longer narrative, and a
// repeat of a known tactic is not.
func TestStorylineReraisesOnNewTactic(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.Storyline.Threshold = 2 })

	first := feed(e, cat.open(0, "/etc/shadow"), exploit.setuid(time.Second, 0))
	if n := len(byRule(first, RuleNameAttackChain)); n != 1 {
		t.Fatalf("threshold 2: got %d chains after two tactics, want 1", n)
	}

	repeat := feed(e, cat.open(2*time.Second, "/etc/gshadow"))
	if n := len(byRule(repeat, RuleNameAttackChain)); n != 0 {
		t.Fatal("a repeated tactic re-raised the chain")
	}

	more := feed(e, exploit.ptrace(3*time.Second, 1))
	chains := byRule(more, RuleNameAttackChain)
	if len(chains) != 1 {
		t.Fatalf("a new tactic did not re-raise the chain")
	}
	if !strings.Contains(chains[0].Args["tactics"], "Defense Evasion") {
		t.Errorf("re-raised chain is missing the new tactic: %s", chains[0].Args["tactics"])
	}
}

// TestStorylineWindowExpiry: activity separated by more than the window is two
// stories, not one slow intrusion.
func TestStorylineWindowExpiry(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.Storyline.Window = time.Minute })

	a1 := feed(e, cat.open(0, "/etc/shadow"))
	a2 := feed(e, exploit.setuid(2*time.Minute, 0))

	if a1[0].Storyline == a2[0].Storyline {
		t.Errorf("alerts two minutes apart with a one-minute window share storyline %q", a1[0].Storyline)
	}
}

// TestStorylineMerge: two stories that later turn out to share an ancestor
// become one, keeping the older id.
func TestStorylineMerge(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.Storyline.Threshold = 3 })

	// Parentage of 400 and 399 is unknown at first, so these open two
	// separate stories: [401, 400] and [402, 399].
	a := feed(e,
		proc{pid: 401, ppid: 400, comm: "cat", uid: 1000}.open(0, "/etc/shadow"),
		proc{pid: 402, ppid: 399, comm: "exploit", uid: 1000}.setuid(time.Second, 0),
	)
	if a[0].Storyline == a[1].Storyline {
		t.Fatal("unrelated processes shared a storyline before any link was seen")
	}
	older := a[0].Storyline

	// 400 is revealed as a child of 399. Its alert's chain [400, 399]
	// touches both stories, which must merge — and the merged story now
	// spans three tactics.
	merged := feed(e, proc{pid: 400, ppid: 399, comm: "sh", uid: 1000}.ptrace(2*time.Second, 1))

	chains := byRule(merged, RuleNameAttackChain)
	if len(chains) != 1 {
		t.Fatalf("merge did not produce an attack chain: %v", ruleNames(merged))
	}
	if chains[0].Storyline != older {
		t.Errorf("merged storyline id = %q, want the older %q", chains[0].Storyline, older)
	}
	if len(chains[0].Story) != 3 {
		t.Errorf("merged story has %d steps, want 3", len(chains[0].Story))
	}
}

// TestStorylineLookupFillsGaps: a grandparent that never made a monitored
// syscall is still found through the injected lookup, so the walk stops at
// the real session boundary rather than at the first unknown process.
func TestStorylineLookupFillsGaps(t *testing.T) {
	known := map[uint32]struct {
		ppid uint32
		comm string
	}{
		100: {50, "bash"},
		50:  {1, "sshd"},
	}

	e := storyEngine(t, func(c *Config) {
		c.Storyline.Lookup = func(pid uint32) (uint32, string, bool) {
			p, ok := known[pid]
			return p.ppid, p.comm, ok
		}
		c.Storyline.Threshold = 2
	})

	// Neither bash nor sshd ever appears in the event stream.
	a := feed(e, cat.open(0, "/etc/shadow"), exploit.setuid(time.Second, 0))

	chains := byRule(a, RuleNameAttackChain)
	if len(chains) != 1 {
		t.Fatalf("siblings were not linked through a looked-up parent: %v", ruleNames(a))
	}
	if got := chains[0].Args["root"]; got != "bash[100]" {
		t.Errorf("root = %q, want bash[100]", got)
	}
}

func TestStorylineDisabled(t *testing.T) {
	e := storyEngine(t, func(c *Config) { c.Storyline.Enabled = false })

	a := feed(e, cat.open(0, "/etc/shadow"), exploit.setuid(time.Second, 0))
	a = append(a, feed(e, python3.revshell(2*time.Second)...)...)

	for _, al := range a {
		if al.Rule == RuleNameAttackChain || al.Storyline != "" {
			t.Fatalf("correlation disabled but got %s with storyline %q", al.Rule, al.Storyline)
		}
	}
}

func TestTacticsFor(t *testing.T) {
	cases := []struct {
		rule, mitre string
		want        string
	}{
		{RuleNameSensitiveFile, "T1003.008", "Credential Access"},
		{RuleNameSensitiveFile, "T1552.004", "Credential Access"},
		{RuleNamePrivilegeEscalation, "T1548.001", "Privilege Escalation"},
		{RuleNameProcessInjection, "T1055.008", "Defense Evasion"},
		{RuleNameReverseShell, "T1059", "Execution + Command and Control"},
		{"future-rule", "T9999", ""},
	}

	for _, c := range cases {
		got := tacticNames(TacticsFor(&Alert{Rule: c.rule, MitreID: c.mitre}))
		if got != c.want {
			t.Errorf("TacticsFor(%s, %s) = %q, want %q", c.rule, c.mitre, got, c.want)
		}
	}
}

// Every technique a rule can report must roll up to a tactic, or alerts from
// that rule would be invisible to correlation.
func TestEveryRuleTechniqueHasATactic(t *testing.T) {
	for _, r := range AllRules() {
		for _, tech := range r.Techniques {
			if len(TacticsFor(&Alert{Rule: r.Name, MitreID: tech.ID})) == 0 {
				t.Errorf("rule %s technique %s maps to no ATT&CK tactic", r.Name, tech.ID)
			}
		}
	}
}

func ruleNames(alerts []*Alert) []string {
	out := make([]string, len(alerts))
	for i, a := range alerts {
		out[i] = a.Rule
	}
	return out
}

// TestStorylineKeepsTurningPointsWhenFull reproduces what the end-to-end run
// on a real kernel exposed: a noisy story filled its step budget with
// credential reads, and the reverse shell that completed the chain — the most
// important step — was the one dropped.
func TestStorylineKeepsTurningPointsWhenFull(t *testing.T) {
	e := storyEngine(t)

	evs := []events.Event{cat.open(0, "/etc/shadow")}
	for i := 1; i <= 2*maxStorySteps; i++ {
		evs = append(evs, proc{pid: 500 + uint32(i), ppid: 100, comm: "grep", uid: 1000}.
			open(time.Duration(i)*time.Millisecond, "/etc/shadow"))
	}
	evs = append(evs, exploit.setuid(time.Second, 0))
	alerts := feed(e, evs...)
	alerts = append(alerts, feed(e, python3.revshell(2*time.Second)...)...)

	chains := byRule(alerts, RuleNameAttackChain)
	if len(chains) != 1 {
		t.Fatalf("got %d chains, want 1", len(chains))
	}
	story := chains[0].Story

	if len(story) != maxStorySteps {
		t.Errorf("story has %d steps, want the cap %d", len(story), maxStorySteps)
	}
	if story[0].Summary != "openat /etc/shadow" || story[0].Comm != "cat" {
		t.Errorf("first turning point lost: %+v", story[0])
	}
	last := story[len(story)-1]
	if !strings.HasPrefix(last.Summary, "reverse shell") {
		t.Errorf("final step is %q, want the reverse shell", last.Summary)
	}

	var sawSetuid bool
	for _, st := range story {
		if st.Summary == "setuid(0)" {
			sawSetuid = true
		}
	}
	if !sawSetuid {
		t.Error("the privilege-escalation turning point was evicted")
	}
}
