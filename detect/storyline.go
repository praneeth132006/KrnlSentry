package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Storylines: from isolated alerts to attack chains.
//
// Every rule in this package judges one process at one moment. Real intrusions
// do not look like that. They look like a shell that reads ~/.aws/credentials,
// whose child ptraces a neighbour, whose grandchild calls setuid(0), and whose
// great-grandchild dials out — four alerts, four PIDs, four different rules, and
// a SOC queue that shows them as four unrelated MEDIUM/HIGH items an hour apart
// in triage order.
//
// The correlator stitches them back together. It keeps a lightweight process
// lineage built from every event the agent sees, files each alert into a
// *storyline* keyed by the process tree it happened in, and maps each alert to
// the ATT&CK *tactic* it represents (what the attacker was trying to achieve,
// one level above the technique). When one storyline spans enough distinct
// tactics, it raises a single synthesised `attack-chain` alert that carries the
// whole narrative in order:
//
//	CRITICAL attack-chain  python3[4127]
//	  Multi-stage attack in the process tree of bash[4100]: Credential Access →
//	  Privilege Escalation → Execution → Command and Control (4 tactics, 5
//	  alerts, 3 processes, 2.4s)
//
// Two properties make this more than "group by PPID":
//
//   - Session boundaries. Walking up from an alerting process stops at the
//     process that *owns* a session — sshd, systemd, containerd-shim, a
//     terminal multiplexer — and at PID 1. Without that, every process on the
//     host shares init as an ancestor and the whole machine becomes one story.
//     With it, each SSH login, each container and each daemon is its own scope.
//
//   - Tactic diversity, not alert volume. A process reading /etc/shadow fifty
//     times is one tactic, however noisy. Three *different* attacker goals
//     inside one process tree within minutes of each other is the shape of an
//     intrusion, and almost never the shape of administration.
//
// Like the rules, this is pure: no clock reads (time comes from the events'
// monotonic timestamps), and the only ambient access is an injected ProcLookup
// that a test or a replay can leave nil.

// Tactic is a MITRE ATT&CK tactic: the "why" above a technique's "how".
type Tactic struct {
	ID   string
	Name string
}

// The tactics this tool's techniques roll up to.
var (
	TacticExecution        = Tactic{"TA0002", "Execution"}
	TacticPrivEsc          = Tactic{"TA0004", "Privilege Escalation"}
	TacticDefenseEvasion   = Tactic{"TA0005", "Defense Evasion"}
	TacticCredentialAccess = Tactic{"TA0006", "Credential Access"}
	TacticCommandControl   = Tactic{"TA0011", "Command and Control"}
)

// tacticsByTechnique maps a technique's parent ID to its primary tactic.
//
// ATT&CK lists several techniques under more than one tactic (T1055 is both
// Defense Evasion and Privilege Escalation). One is chosen per technique, the
// one that best describes what *this tool's* detection of it means, so that a
// single alert can never inflate a storyline's tactic count by itself.
var tacticsByTechnique = map[string]Tactic{
	"T1548": TacticPrivEsc,
	"T1068": TacticPrivEsc,
	"T1003": TacticCredentialAccess,
	"T1552": TacticCredentialAccess,
	"T1055": TacticDefenseEvasion,
	"T1059": TacticExecution,
	"T1071": TacticCommandControl,
}

// TacticsFor returns the ATT&CK tactics an alert evidences.
//
// The reverse shell is the one deliberate exception to "one tactic per alert":
// a completed socket → dup2 → execve chain is simultaneously code execution and
// an interactive command channel, and calling it only "Execution" would rank it
// alongside a cron job running a script.
func TacticsFor(a *Alert) []Tactic {
	parent, _, _ := strings.Cut(a.MitreID, ".")

	var out []Tactic
	if t, ok := tacticsByTechnique[parent]; ok {
		out = append(out, t)
	}
	if a.Rule == RuleNameReverseShell {
		out = append(out, TacticCommandControl)
	}
	return out
}

// RuleNameAttackChain is the rule name carried by synthesised storyline alerts.
// Like the other rule names it is a public contract.
const RuleNameAttackChain = "attack-chain"

// ProcLookup resolves a process the event stream has not described yet.
//
// The lineage learns parentage from events, but an alert's grandparent may not
// have made a monitored syscall since the agent started. The live agent passes
// a /proc reader; tests and replays pass nil and rely on the capture alone.
type ProcLookup func(pid uint32) (ppid uint32, comm string, ok bool)

// StorylineConfig tunes the correlator.
type StorylineConfig struct {
	// Enabled turns correlation on. When off, alerts carry no storyline id
	// and no attack-chain alert is ever raised.
	Enabled bool

	// Threshold is how many distinct tactics one storyline must span before
	// an attack-chain alert is raised. Each further tactic re-raises it with
	// the longer story.
	Threshold int

	// Window is how long a storyline stays open after its most recent
	// alert. Inactivity, not total age: a slow intrusion that keeps making
	// progress stays one story.
	Window time.Duration

	// Lookup fills lineage gaps. Optional.
	Lookup ProcLookup
}

// DefaultStorylineConfig returns the settings the CLI starts from.
func DefaultStorylineConfig() StorylineConfig {
	return StorylineConfig{
		Enabled:   true,
		Threshold: 3,
		Window:    10 * time.Minute,
	}
}

// StoryStep is one alert's contribution to a storyline, as reported in the
// attack-chain alert's "story" field.
type StoryStep struct {
	OffsetMS int64  `json:"offset_ms"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Rule     string `json:"rule"`
	MitreID  string `json:"mitre_id"`
	Tactic   string `json:"tactic"`
	Summary  string `json:"summary"`

	// pivotal marks a step that introduced a tactic to the story. Such steps
	// are never evicted when the story is full: they are the story.
	pivotal bool
}

// sessionBoundaries are processes whose children belong to separate stories.
//
// Each of these either owns a login session, supervises unrelated services, or
// is the root of a container. Matching is on comm and therefore spoofable — a
// process naming itself "sshd" splits its own story in two. That is a loss of
// correlation, not of detection: every underlying alert still fires.
var sessionBoundaries = map[string]bool{
	"systemd":                 true,
	"init":                    true,
	"sshd":                    true,
	"sshd-session":            true,
	"login":                   true,
	"containerd-shim":         true,
	"containerd-shim-runc-v2": true,
	"conmon":                  true,
	"runc":                    true,
	"cron":                    true,
	"crond":                   true,
	"tmux: server":            true,
	"screen":                  true,
	"kthreadd":                true,
}

// Correlator bounds. Deep enough for any shell pipeline, small enough that an
// adversarial PPID cycle cannot spin.
const (
	maxAncestry       = 16
	maxStorySteps     = 24
	maxLineage        = 1 << 16
	lineageSweepEvery = 30 * time.Second
)

type procNode struct {
	ppid     uint32
	comm     string
	lastSeen uint64
}

type storyline struct {
	id       string
	root     uint32
	rootComm string

	members map[uint32]bool

	tactics    []Tactic
	techniques []string
	procs      []string
	steps      []StoryStep

	alerts    int
	firstTS   uint64
	lastTS    uint64
	reportedN int // tactic count at the last attack-chain alert
}

// addStep appends a step, making room when the story is full by evicting the
// oldest step that did not introduce a tactic. A noisy story therefore keeps
// its turning points and its most recent context, rather than its first
// twenty-four steps and none of the ending.
func (s *storyline) addStep(st StoryStep) {
	if len(s.steps) >= maxStorySteps {
		evict := -1
		for i, have := range s.steps {
			if !have.pivotal {
				evict = i
				break
			}
		}
		if evict < 0 {
			if !st.pivotal {
				return
			}
			evict = 0 // only possible with more tactics than slots
		}
		s.steps = append(s.steps[:evict], s.steps[evict+1:]...)
	}
	s.steps = append(s.steps, st)
}

func (s *storyline) hasTactic(t Tactic) bool {
	for _, have := range s.tactics {
		if have == t {
			return true
		}
	}
	return false
}

// Correlator groups alerts into storylines. Not safe for concurrent use; the
// Engine that owns it serialises access.
type Correlator struct {
	cfg StorylineConfig

	lineage map[uint32]*procNode
	byPID   map[uint32]*storyline

	seq       uint64
	lastSweep uint64
	chains    uint64
}

// NewCorrelator returns a correlator, or nil if correlation is disabled. All
// methods are nil-safe, so callers need not check.
func NewCorrelator(cfg StorylineConfig) *Correlator {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Threshold < 2 {
		// A threshold of one would turn every alert into an attack
		// chain, which is a second copy of the alert stream, not a
		// correlation.
		cfg.Threshold = 2
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultStorylineConfig().Window
	}

	return &Correlator{
		cfg:     cfg,
		lineage: make(map[uint32]*procNode),
		byPID:   make(map[uint32]*storyline),
	}
}

// Observe records an event's parentage. Called for every event, alerting or
// not, because the processes that stitch a story together — the shell between
// two alerting children — are usually the ones that never alert themselves.
func (c *Correlator) Observe(ev events.Event) {
	if c == nil || ev.PID == 0 {
		return
	}

	c.maybeSweep(ev.Timestamp)

	n, ok := c.lineage[ev.PID]
	if !ok {
		n = &procNode{}
		c.lineage[ev.PID] = n
	}
	n.ppid = ev.PPID
	n.comm = ev.Comm
	n.lastSeen = ev.Timestamp
}

// Storylines reports how many storylines are open. Used for stats.
func (c *Correlator) Storylines() int {
	if c == nil {
		return 0
	}
	seen := make(map[*storyline]bool)
	for _, s := range c.byPID {
		seen[s] = true
	}
	return len(seen)
}

// Chains reports how many attack-chain alerts have been raised.
func (c *Correlator) Chains() uint64 {
	if c == nil {
		return 0
	}
	return c.chains
}

// Correlate files an alert into its storyline, stamps the storyline id on it,
// and returns an attack-chain alert if this alert pushed the story over the
// threshold (or extended a story already over it with a new tactic).
func (c *Correlator) Correlate(ev events.Event, a *Alert) *Alert {
	if c == nil || a == nil {
		return nil
	}

	now := ev.Timestamp
	chain := c.ancestry(ev.PID, ev.PPID, now)

	s := c.storyFor(chain, now)
	a.Storyline = s.id

	s.alerts++
	s.lastTS = now

	newTactic := false
	for _, t := range TacticsFor(a) {
		if !s.hasTactic(t) {
			s.tactics = append(s.tactics, t)
			newTactic = true
		}
	}
	appendUnique(&s.techniques, a.MitreID)
	appendUnique(&s.procs, fmt.Sprintf("%s[%d]", a.Comm, a.PID))

	s.addStep(StoryStep{
		OffsetMS: int64(time.Duration(now-s.firstTS) / time.Millisecond),
		PID:      a.PID,
		Comm:     a.Comm,
		Rule:     a.Rule,
		MitreID:  a.MitreID,
		Tactic:   tacticNames(TacticsFor(a)),
		Summary:  stepSummary(a),
		pivotal:  newTactic,
	})

	if !newTactic || len(s.tactics) < c.cfg.Threshold || len(s.tactics) <= s.reportedN {
		return nil
	}

	s.reportedN = len(s.tactics)
	c.chains++

	return c.chainAlert(ev, a, s)
}

// ancestry returns pid followed by its ancestors, stopping below the nearest
// session boundary. The alerting process itself is always included, even when
// it is a boundary, so that sshd reading /etc/shadow still gets a story.
func (c *Correlator) ancestry(pid, ppid uint32, now uint64) []uint32 {
	chain := []uint32{pid}
	seen := map[uint32]bool{pid: true}

	cur := ppid
	for len(chain) < maxAncestry {
		if cur <= 2 || seen[cur] {
			break // init, kthreadd, the idle task, or a cycle
		}

		n := c.node(cur, now)
		if n != nil && sessionBoundaries[n.comm] {
			break
		}

		chain = append(chain, cur)
		seen[cur] = true

		if n == nil {
			break // parentage unknown beyond here
		}
		cur = n.ppid
	}

	return chain
}

// node returns what is known about pid, consulting the injected lookup for a
// process the stream has not yet described and caching the answer.
func (c *Correlator) node(pid uint32, now uint64) *procNode {
	if n, ok := c.lineage[pid]; ok {
		return n
	}
	if c.cfg.Lookup == nil {
		return nil
	}

	ppid, comm, ok := c.cfg.Lookup(pid)
	if !ok {
		return nil
	}

	n := &procNode{ppid: ppid, comm: comm, lastSeen: now}
	c.lineage[pid] = n
	return n
}

// storyFor finds the open storyline any process in chain already belongs to,
// merging stories that the chain reveals to be one, or opens a new one.
func (c *Correlator) storyFor(chain []uint32, now uint64) *storyline {
	window := uint64(c.cfg.Window)

	var found []*storyline
	for _, pid := range chain {
		s, ok := c.byPID[pid]
		if !ok {
			continue
		}
		if now > s.lastTS && now-s.lastTS > window {
			continue // expired; the sweep will collect it
		}
		if !containsStory(found, s) {
			found = append(found, s)
		}
	}

	var s *storyline
	switch len(found) {
	case 0:
		c.seq++
		top := chain[len(chain)-1]
		s = &storyline{
			id:       fmt.Sprintf("ks-%d-%d", top, c.seq),
			root:     top,
			rootComm: c.commOf(top),
			members:  make(map[uint32]bool),
			firstTS:  now,
		}
	default:
		// The oldest story absorbs the rest so its id — which earlier
		// alerts already carry — stays the canonical one.
		s = found[0]
		for _, other := range found[1:] {
			if other.firstTS < s.firstTS {
				s, other = other, s
			}
			c.merge(s, other)
		}
	}

	for _, pid := range chain {
		s.members[pid] = true
		c.byPID[pid] = s
	}

	// The topmost process of the newest chain becomes the root if the old
	// root is beneath it — i.e. we have now seen further up the same tree.
	if top := chain[len(chain)-1]; top != s.root {
		for _, pid := range chain {
			if pid == s.root {
				s.root = top
				s.rootComm = c.commOf(top)
				break
			}
		}
	}

	return s
}

// merge folds src into dst.
func (c *Correlator) merge(dst, src *storyline) {
	for pid := range src.members {
		dst.members[pid] = true
		c.byPID[pid] = dst
	}
	for _, t := range src.tactics {
		if !dst.hasTactic(t) {
			dst.tactics = append(dst.tactics, t)
		}
	}
	for _, t := range src.techniques {
		appendUnique(&dst.techniques, t)
	}
	for _, p := range src.procs {
		appendUnique(&dst.procs, p)
	}
	shift := int64(time.Duration(src.firstTS-dst.firstTS) / time.Millisecond)
	merged := append([]StoryStep(nil), dst.steps...)
	for _, st := range src.steps {
		st.OffsetMS += shift
		merged = append(merged, st)
	}
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].OffsetMS < merged[j].OffsetMS })
	dst.steps = dst.steps[:0]
	for _, st := range merged {
		dst.addStep(st)
	}
	dst.alerts += src.alerts
	if src.lastTS > dst.lastTS {
		dst.lastTS = src.lastTS
	}
	if src.reportedN > dst.reportedN {
		dst.reportedN = src.reportedN
	}
}

func (c *Correlator) commOf(pid uint32) string {
	if n, ok := c.lineage[pid]; ok {
		return n.comm
	}
	return "?"
}

// chainAlert builds the synthesised attack-chain alert.
func (c *Correlator) chainAlert(ev events.Event, trigger *Alert, s *storyline) *Alert {
	names := make([]string, len(s.tactics))
	ids := make([]string, len(s.tactics))
	for i, t := range s.tactics {
		names[i] = t.Name
		ids[i] = t.ID
	}

	span := time.Duration(s.lastTS - s.firstTS)
	root := fmt.Sprintf("%s[%d]", s.rootComm, s.root)

	steps := make([]StoryStep, len(s.steps))
	copy(steps, s.steps)

	return &Alert{
		Timestamp: trigger.Timestamp,
		PID:       trigger.PID,
		TID:       trigger.TID,
		PPID:      trigger.PPID,
		Comm:      trigger.Comm,
		UID:       trigger.UID,
		GID:       trigger.GID,
		Syscall:   trigger.Syscall,
		Args: map[string]string{
			"tactics":     strings.Join(names, " → "),
			"tactic_ids":  strings.Join(ids, ","),
			"techniques":  strings.Join(s.techniques, ","),
			"processes":   strings.Join(s.procs, ","),
			"root":        root,
			"alert_count": fmt.Sprintf("%d", s.alerts),
			"span_ms":     fmt.Sprintf("%d", span/time.Millisecond),
		},
		MitreID:        strings.Join(s.techniques, ","),
		MitreTechnique: "Multi-stage attack: " + strings.Join(names, ", "),
		Severity:       SeverityCritical,
		Description: fmt.Sprintf(
			"Multi-stage attack in the process tree of %s: %s (%d tactics, %d alerts, %d processes, %s)",
			root, strings.Join(names, " → "), len(s.tactics), s.alerts, len(s.procs),
			span.Round(time.Millisecond)),
		Rule:      RuleNameAttackChain,
		Storyline: s.id,
		Story:     steps,
	}
}

// maybeSweep expires idle storylines and lineage, at most every
// lineageSweepEvery. Driven by event time, like the Tracker, so an idle
// machine does no work and a replay behaves exactly like the live run.
func (c *Correlator) maybeSweep(now uint64) {
	if c.lastSweep != 0 && now-c.lastSweep < uint64(lineageSweepEvery) && len(c.lineage) < maxLineage {
		return
	}
	c.lastSweep = now

	window := uint64(c.cfg.Window)

	for pid, s := range c.byPID {
		if now > s.lastTS && now-s.lastTS > window {
			delete(c.byPID, pid)
		}
	}

	for pid, n := range c.lineage {
		if c.byPID[pid] != nil {
			continue // a live story still needs to resolve through it
		}
		if now > n.lastSeen && now-n.lastSeen > window {
			delete(c.lineage, pid)
		}
	}

	// Same crude-but-bounded fallback as the Tracker: under a genuine fork
	// storm, forget parentage rather than grow without limit. Stories keep
	// their member sets, so in-flight correlation degrades gracefully.
	if len(c.lineage) >= maxLineage {
		c.lineage = make(map[uint32]*procNode, maxLineage/2)
	}
}

// stepSummary condenses an alert into a few words for the story timeline.
func stepSummary(a *Alert) string {
	switch a.Rule {
	case RuleNameReverseShell:
		if d := a.Args["chain_dest"]; d != "" {
			return "reverse shell to " + d
		}
		return "reverse shell"
	case RuleNameProcessInjection:
		return fmt.Sprintf("ptrace %s → pid %s", a.Args["request"], a.Args["target_pid"])
	}

	if p := a.Args["path"]; p != "" {
		return a.Syscall + " " + p
	}

	for _, k := range []string{"target_uid", "target_gid"} {
		if v, ok := a.Args[k]; ok {
			return fmt.Sprintf("%s(%s)", a.Syscall, v)
		}
	}
	if v, ok := a.Args["ruid"]; ok {
		return fmt.Sprintf("%s(%s,%s,%s)", a.Syscall, v, a.Args["euid"], a.Args["suid"])
	}
	if v, ok := a.Args["rgid"]; ok {
		return fmt.Sprintf("%s(%s,%s,%s)", a.Syscall, v, a.Args["egid"], a.Args["sgid"])
	}

	return a.Syscall
}

func tacticNames(ts []Tactic) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = t.Name
	}
	return strings.Join(names, " + ")
}

func appendUnique(list *[]string, v string) {
	for _, have := range *list {
		if have == v {
			return
		}
	}
	*list = append(*list, v)
}

func containsStory(list []*storyline, s *storyline) bool {
	for _, have := range list {
		if have == s {
			return true
		}
	}
	return false
}
