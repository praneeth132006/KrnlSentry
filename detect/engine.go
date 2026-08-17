package detect

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// StatFunc looks up filesystem metadata for a path.
//
// It is a field on Config rather than a direct call to os.Stat so that the SUID
// rule can be unit tested. Testing "did this process execute a setuid binary?"
// otherwise requires creating a real setuid file, which requires root — turning
// a one-line table test into something CI cannot run. Injecting the lookup
// keeps every rule a pure function of its inputs.
type StatFunc func(path string) (fs.FileInfo, error)

// Config holds the tunable parameters of the detection engine.
//
// The zero value is not usable; call DefaultConfig and adjust.
type Config struct {
	// RevShellWindow is how long the socket→connect→dup2→execve sequence
	// may take and still be considered one chain.
	RevShellWindow time.Duration

	// DebuggerComms are process names exempt from the ptrace rule.
	//
	// This is comm-based, and comm is trivially spoofable — a payload that
	// names itself "gdb" walks straight past this check. It is the MVP
	// approach from the spec and is documented as a known weakness in the
	// README rather than presented as a control.
	DebuggerComms []string

	// IgnoreLoopback suppresses the reverse-shell rule for connections to
	// 127.0.0.0/8. Off by default — a loopback reverse shell is still a
	// reverse shell, and local pivoting is real. The test scripts in test/
	// connect only to loopback, so this exists to let someone run the demo
	// without noise, not because loopback is safe.
	IgnoreLoopback bool

	// IgnoreSelfProc suppresses sensitive-file alerts when a process reads
	// its own /proc entry. Off by default so behaviour matches the spec,
	// but it is the first knob to reach for on a host running allocators or
	// sanitizers that read /proc/self/maps routinely.
	IgnoreSelfProc bool

	// Stat resolves executed paths for the SUID check.
	Stat StatFunc

	// SelfPID is this agent's own process id. Events from it are dropped in
	// the kernel already; this is a second, cheap guard so that a change to
	// the kernel filter cannot reintroduce a self-alerting loop.
	SelfPID uint32
}

// DefaultConfig returns the configuration the CLI starts from.
func DefaultConfig() Config {
	return Config{
		RevShellWindow: 2 * time.Second,
		DebuggerComms:  []string{"gdb", "gdbserver", "strace", "ltrace", "lldb", "lldb-server"},
		IgnoreLoopback: false,
		Stat:           os.Stat,
		SelfPID:        uint32(os.Getpid()),
	}
}

// Context is everything a rule is allowed to see.
//
// Rules receive this and return an alert or nil. They must not reach outside
// it — no globals, no ambient filesystem access except through Config.Stat, no
// clock reads. That restriction is what makes the whole detection surface
// reproducible from a JSONL capture.
type Context struct {
	// Event is the observation being evaluated.
	Event events.Event

	// History is the recent syscall history of Event's process. Nil for
	// syscalls no sequence rule tracks — ProcessHistory's methods are
	// nil-safe, so rules need not check.
	History *ProcessHistory

	// Config carries tunables and the injected Stat.
	Config *Config
}

// Rule names.
//
// Declared as constants rather than read back from the Rule values because a
// rule's Eval function needs its own name when building an alert, and a Rule
// literal that refers to a function that refers to the literal is an
// initialization cycle Go rejects at compile time.
//
// These strings are a public contract: they appear in every alert's "rule"
// field and in --rules. Changing one breaks other people's filters and
// dashboards, so treat them as frozen once released.
const (
	RuleNamePrivilegeEscalation = "privilege-escalation"
	RuleNameSensitiveFile       = "sensitive-file-access"
	RuleNameProcessInjection    = "process-injection"
	RuleNameReverseShell        = "reverse-shell"
)

// Rule is one detection.
//
// Name is the stable identifier used by --rules and must not change once
// released; it appears in every alert this rule produces and people build
// filters on it.
type Rule struct {
	Name        string
	Description string

	// Techniques lists the ATT&CK techniques this rule can report. Used to
	// generate the detection table in the README, so it is documentation
	// that cannot drift from the code.
	Techniques []Technique

	// Eval returns an alert, or nil if the event is unremarkable.
	//
	// One alert per event at most. If an event genuinely satisfies two
	// rules, both fire — but a single rule reporting the same event twice
	// is a bug, not a feature.
	Eval func(Context) *Alert
}

// allRules is the registry. A rule that is not in this slice does not exist as
// far as the CLI is concerned.
//
// Order determines evaluation order and therefore the order alerts appear when
// one event trips several rules. Cheapest and most specific first.
var allRules = []Rule{
	rulePrivilegeEscalation,
	ruleSensitiveFileAccess,
	rulePtraceInjection,
	ruleReverseShell,
}

// AllRules returns the full rule registry.
func AllRules() []Rule {
	out := make([]Rule, len(allRules))
	copy(out, allRules)
	return out
}

// RuleNames returns every rule name, sorted, for help text and error messages.
func RuleNames() []string {
	names := make([]string, 0, len(allRules))
	for _, r := range allRules {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// Engine evaluates events against the enabled rules.
type Engine struct {
	rules   []Rule
	tracker *Tracker
	cfg     Config
}

// NewEngine builds an engine running the named rules.
//
// An empty or nil enabled list means all rules. Unknown names are an error
// rather than a warning: someone who typed --rules=revshel intended to run a
// rule, and starting up having silently enabled nothing is the worst possible
// response — the tool would look healthy while detecting nothing.
func NewEngine(cfg Config, enabled []string) (*Engine, error) {
	if cfg.Stat == nil {
		cfg.Stat = os.Stat
	}
	if cfg.RevShellWindow <= 0 {
		cfg.RevShellWindow = DefaultConfig().RevShellWindow
	}

	e := &Engine{
		tracker: NewTracker(),
		cfg:     cfg,
	}

	if len(enabled) == 0 {
		e.rules = AllRules()
		return e, nil
	}

	wanted := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		wanted[name] = true
	}

	for _, r := range allRules {
		if wanted[r.Name] {
			e.rules = append(e.rules, r)
			delete(wanted, r.Name)
		}
	}

	if len(wanted) > 0 {
		unknown := make([]string, 0, len(wanted))
		for name := range wanted {
			unknown = append(unknown, name)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown rule(s): %s (available: %s)",
			strings.Join(unknown, ", "), strings.Join(RuleNames(), ", "))
	}

	if len(e.rules) == 0 {
		return nil, fmt.Errorf("no rules enabled (available: %s)", strings.Join(RuleNames(), ", "))
	}

	return e, nil
}

// Rules returns the enabled rules.
func (e *Engine) Rules() []Rule { return e.rules }

// Tracker exposes the process tracker, for stats reporting and for the agent to
// forget exited processes.
func (e *Engine) Tracker() *Tracker { return e.tracker }

// Evaluate runs every enabled rule against one event.
//
// The tracker is updated before rules run, so a rule looking at History sees
// the current event as the most recent entry. That matters for the reverse-shell
// rule, which fires on the execve that completes the chain and needs that
// execve to be present in the history it examines.
func (e *Engine) Evaluate(ev events.Event) []*Alert {
	// Belt and braces against the self-alerting feedback loop. The kernel
	// already filters our own events; this makes the guarantee independent
	// of that filter still being correct.
	if ev.PID == e.cfg.SelfPID {
		return nil
	}

	history := e.tracker.Record(ev)

	ctx := Context{
		Event:   ev,
		History: history,
		Config:  &e.cfg,
	}

	var alerts []*Alert
	for _, r := range e.rules {
		if alert := r.Eval(ctx); alert != nil {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}
