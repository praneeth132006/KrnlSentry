package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/praneeth132006/KrnlSentry/detect"
)

// Dashboard is a full-screen, repainting status display for a live run.
//
// The ConsoleSink's doc comment argues — correctly — that a scrolling line per
// alert is the right *default*: it pipes, greps, redirects and survives SSH.
// This type does not replace it, it is opted into with --dashboard, and it
// refuses to run when stdout is not a terminal precisely so that nobody ever
// gets a screenful of escape codes in a log file.
//
// What it buys, when a human is actually watching, is the thing a scrolling
// stream cannot give: standing totals. Mid-incident the question is rarely
// "what was the last alert" — it is "how many, how bad, which rules, which
// processes, is a chain forming, are we dropping events". Those answers scroll
// off the top of a stream within seconds on a busy host; here they are always
// on screen, and the alert feed is one panel of several rather than the whole
// output.
//
// Every number shown is either counted from the alerts written to this sink or
// read through the Metrics hook. The dashboard computes nothing about what is
// suspicious and holds no detection state — it is a view, and detect/ remains
// the only package that decides anything.
type Dashboard struct {
	mu   sync.Mutex
	w    io.Writer
	opts DashboardOptions

	started time.Time
	painted bool
	closed  bool

	// Counters derived from the alert stream.
	total      uint64
	bySeverity map[detect.Severity]uint64
	byRule     map[string]uint64
	byTactic   map[string]uint64
	byProcess  map[procKey]uint64
	recent     []*detect.Alert
	lastChain  *detect.Alert

	stop chan struct{}
	done chan struct{}
}

// procKey identifies one process in the "top processes" panel. PID is part of
// the key because two unrelated processes sharing a comm ("bash") are two
// findings, and collapsing them would hide a per-process alert count — the
// number most likely to point at the process worth killing.
type procKey struct {
	Comm string
	PID  uint32
}

// Metrics are the run-level figures the dashboard cannot derive from alerts.
//
// They are pulled through a hook rather than pushed, because the authoritative
// copies are atomics owned by the agent's pipeline and the engine's own
// counters. Reading them at paint time means the display cannot drift from
// them, and no counter has to be mirrored into this package.
type Metrics struct {
	Observed     uint64 // events that passed the scope filter
	QueueDropped uint64 // dropped between collector and engine
	KernelEvents uint64 // events the BPF program produced
	KernelDrops  uint64 // events the ring buffer could not hold
	WriteErrors  uint64

	TrackedProcs int    // processes in the state tracker
	Storylines   int    // storylines currently open
	AttackChains uint64 // attack-chain alerts raised
	Suppressed   uint64 // alerts folded by deduplication

	// Progress is replay completion in [0,1]. Negative means "not
	// applicable", which is what a live run reports.
	Progress float64
}

// DashboardOptions configures the display. The zero value is usable; only
// Metrics is really worth setting.
type DashboardOptions struct {
	Version   string
	Mode      string   // "live" or "replay"
	Scope     string   // "system-wide", "PID 4821 + descendants"
	Source    string   // capture path under --replay; empty when live
	AlertPath string   // where the JSONL log is going
	Rules     []string // enabled rules, so zero-hit rules still show as armed

	// MinSeverity filters the alert feed only. The totals, bars and rule
	// counts always reflect everything the engine raised: a dashboard whose
	// headline number silently excluded LOW alerts would be lying about the
	// run, and the operator sets --min-severity to quieten the feed, not to
	// unsee the host.
	MinSeverity detect.Severity

	Color   bool
	Width   int           // 0 detects from the terminal
	Height  int           // 0 detects from the terminal
	Refresh time.Duration // 0 uses defaultRefresh

	// Metrics is called on every paint. It must be safe to call from
	// another goroutine and must not block.
	Metrics func() Metrics

	// Now is injectable so tests can render a deterministic uptime.
	Now func() time.Time
}

const (
	// defaultRefresh is fast enough to feel live and slow enough that the
	// repaint itself is never a measurable share of the agent's work.
	defaultRefresh = 250 * time.Millisecond

	// Width bounds. Below the minimum the panels cannot align at all;
	// above the maximum the eye has to travel further than the content
	// justifies, so extra columns are left unused rather than stretched.
	minWidth, maxWidth = 76, 160

	// recentCap is how much alert history is retained. More than can be
	// displayed, so that shrinking the terminal does not lose lines that
	// growing it again would show.
	recentCap = 64

	// Elastic panel bounds. The feed gives up rows before the chain
	// timeline does, because a chain already on screen is a finding and the
	// feed's older entries are also in the alert log.
	maxRecentRows = 12
	minRecentRows = 3
	maxStoryRows  = 8
	minStoryRows  = 2

	maxProcRows = 6

	// MinUsableHeight is the shortest terminal the frame is guaranteed to
	// fit in. Below it the display sheds both context panels and then stops
	// cutting: a frame that scrolls is a worse outcome than a tall one, but
	// a frame missing the alert totals is worse than either.
	MinUsableHeight = 24

	// minDescCols is the narrowest description worth printing; below it the
	// row sheds other columns instead. minNameCols is the floor for the
	// rule and process columns, past which they stop being identifiers.
	minDescCols = 12
	minNameCols = 10
)

// NewDashboard returns a Dashboard writing to w.
func NewDashboard(w io.Writer, opts DashboardOptions) *Dashboard {
	if opts.Refresh <= 0 {
		opts.Refresh = defaultRefresh
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Mode == "" {
		opts.Mode = "live"
	}

	return &Dashboard{
		w:          w,
		opts:       opts,
		started:    opts.Now(),
		bySeverity: make(map[detect.Severity]uint64),
		byRule:     make(map[string]uint64),
		byTactic:   make(map[string]uint64),
		byProcess:  make(map[procKey]uint64),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// DashboardUsable reports whether a full-screen display is appropriate for w.
//
// Checked before the dashboard is built rather than inside it, so the caller
// can fall back to the scrolling console sink and say why.
func DashboardUsable(w io.Writer) bool { return isTerminal(w) }

// Start begins repainting until Close. Calling it is optional: a caller that
// wants to drive the paint itself can call Paint directly.
func (d *Dashboard) Start() {
	go func() {
		defer close(d.done)

		t := time.NewTicker(d.opts.Refresh)
		defer t.Stop()

		// Paint once immediately: an empty dashboard that states what is
		// armed and where alerts go is the startup banner's job, and a
		// quarter-second of blank terminal reads as a hang.
		_ = d.Paint()

		for {
			select {
			case <-d.stop:
				return
			case <-t.C:
				_ = d.Paint()
			}
		}
	}()
}

// Write records one alert. It satisfies Sink.
//
// The alert is counted immediately but drawn on the next paint. Repainting per
// alert would be both slower and less readable under a burst — a screen
// redrawn eight hundred times a second shows nothing at all.
func (d *Dashboard) Write(a *detect.Alert) error {
	if a == nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.total++
	d.bySeverity[a.Severity]++
	d.byRule[a.Rule]++
	d.byProcess[procKey{Comm: a.Comm, PID: a.PID}]++

	for _, t := range detect.TacticsFor(a) {
		d.byTactic[t.Name]++
	}

	if len(a.Story) > 0 {
		d.lastChain = a
	}

	d.recent = append(d.recent, a)
	if len(d.recent) > recentCap {
		d.recent = d.recent[len(d.recent)-recentCap:]
	}

	return nil
}

// Close stops the repaint loop, leaves one final frame on screen and restores
// the cursor.
//
// The last frame is deliberately *not* erased. A run that ends — Ctrl+C, or a
// replay reaching the end of its capture — leaves its totals visible above the
// shutdown summary, so the operator still has the numbers after the tool has
// exited. Wiping the screen on exit, which an alternate-screen TUI does, would
// throw away the one thing they are most likely to want.
func (d *Dashboard) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

	close(d.stop)
	<-d.done

	if err := d.Paint(); err != nil {
		return err
	}

	if d.opts.Color {
		_, err := io.WriteString(d.w, ansiShowCursor)
		return err
	}
	return nil
}

// Paint renders one frame and writes it to the output.
func (d *Dashboard) Paint() error {
	frame := d.Render()

	var b strings.Builder

	if d.opts.Color {
		b.WriteString(ansiHideCursor)
	}

	// Home the cursor and clear downwards rather than clearing the whole
	// screen first. Clearing then drawing leaves the terminal briefly
	// blank, which reads as a flicker on every single frame; overwriting
	// in place and erasing only what the new frame does not cover does not.
	b.WriteString(ansiHome)

	for _, line := range strings.Split(frame, "\n") {
		b.WriteString(line)
		b.WriteString(ansiClearLine)
		b.WriteString("\n")
	}

	b.WriteString(ansiClearBelow)

	d.mu.Lock()
	d.painted = true
	d.mu.Unlock()

	if _, err := io.WriteString(d.w, b.String()); err != nil {
		return fmt.Errorf("painting dashboard: %w", err)
	}
	return nil
}

// ANSI control sequences used only by the dashboard.
const (
	ansiHome       = "\033[H"
	ansiClearLine  = "\033[K"
	ansiClearBelow = "\033[J"
	ansiHideCursor = "\033[?25l"
	ansiShowCursor = "\033[?25h"
)

// Render builds the frame as a string.
//
// Exported and free of I/O so the entire layout is unit-testable: a test feeds
// alerts in, renders, and asserts on the text. Nothing about the display needs
// a terminal to verify.
//
// The frame is fitted to the terminal's height by shrinking the two elastic
// panels — the alert feed first, then the chain timeline — until it fits. That
// is not cosmetic: a frame one line too tall scrolls the terminal, which moves
// the cursor-home position the next repaint draws from, and the display tears
// itself apart within a second. Measuring the rendered frame rather than
// predicting its height from a line count keeps that guarantee true when a
// panel is later added or a long tactic name wraps.
func (d *Dashboard) Render() string {
	h := d.opts.Height
	if h <= 0 {
		h = terminalHeight(d.w)
	}

	// One line spare: the frame is written with a trailing newline per line,
	// so filling the last row exactly would still scroll.
	budget := h - 1

	// Shed in order of what the operator can least afford to lose last:
	// older feed entries (also in the alert log), then chain steps (ditto),
	// then the two context panels — and never the totals.
	lay := layout{
		storyRows:     maxStoryRows,
		recentRows:    maxRecentRows,
		showTactics:   true,
		showProcesses: true,
	}

	for {
		frame := d.render(lay)

		if strings.Count(frame, "\n") <= budget {
			return frame
		}

		switch {
		case lay.recentRows > minRecentRows:
			lay.recentRows--
		case lay.storyRows > minStoryRows:
			lay.storyRows--
		case lay.showProcesses:
			lay.showProcesses = false
		case lay.showTactics:
			lay.showTactics = false
		default:
			// Nothing left to give. A terminal this short cannot hold
			// the panels at all, and cutting further would start
			// removing the headline totals — better to overflow and
			// let the terminal scroll than to show a frame that
			// omits the numbers.
			return frame
		}
	}
}

// layout is how much of each elastic panel one frame gets.
type layout struct {
	storyRows     int
	recentRows    int
	showTactics   bool
	showProcesses bool
}

// render builds one frame with the given elastic panel sizes.
func (d *Dashboard) render(lay layout) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var m Metrics
	if d.opts.Metrics != nil {
		m = d.opts.Metrics()
	}

	w := d.width()
	var b strings.Builder

	d.renderHeader(&b, w, m)
	b.WriteString("\n")
	d.renderSeverityAndRules(&b, w)
	b.WriteString("\n")

	if lay.showTactics {
		d.renderTactics(&b, w)
	}
	if lay.showProcesses {
		if lay.showTactics {
			b.WriteString("\n")
		}
		d.renderProcesses(&b, w)
	}
	if lay.showTactics || lay.showProcesses {
		b.WriteString("\n")
	}

	d.renderStoryline(&b, w, m, lay.storyRows)
	b.WriteString("\n")
	d.renderRecent(&b, w, lay.recentRows)
	b.WriteString("\n")
	d.renderFooter(&b, w, m)

	return b.String()
}

// ── Panels ──────────────────────────────────────────────────────────────────

func (d *Dashboard) renderHeader(b *strings.Builder, w int, m Metrics) {
	mode := strings.ToUpper(d.opts.Mode)
	title := fmt.Sprintf("KrnlSentry %s", d.opts.Version)

	left := fmt.Sprintf("%s · %s · %s", title, mode, d.opts.Scope)
	if d.opts.Source != "" {
		left = fmt.Sprintf("%s · %s", left, d.opts.Source)
	}

	uptime := formatDuration(d.opts.Now().Sub(d.started))

	b.WriteString(d.rule("╭", "╮", w, left, uptime, ansiBold+ansiCyan))
	b.WriteString("\n")

	// One line of the numbers that decide whether anything else on screen
	// can be trusted. Drops come first among the problem counters because a
	// dropped event is an alert that may never have been evaluated at all,
	// which is worse than a write error and far worse than a quiet host.
	stats := []statCell{
		{"events", formatCount(m.Observed), ""},
		{"alerts", formatCount(d.total), d.styleIf(d.total > 0, ansiBold)},
		{"folded", formatCount(m.Suppressed), ""},
		{"tracked", formatCount(uint64(m.TrackedProcs)), ""},
	}

	drops := m.QueueDropped + m.KernelDrops
	stats = append(stats, statCell{"drops", formatCount(drops), d.styleIf(drops > 0, ansiRed+ansiBold)})
	if m.WriteErrors > 0 {
		stats = append(stats, statCell{"write errors", formatCount(m.WriteErrors), ansiRed})
	}

	b.WriteString(d.statLine(stats))
	b.WriteString("\n")

	if m.Progress >= 0 {
		pct := int(m.Progress * 100)
		barW := w - 22
		if barW < 10 {
			barW = 10
		}
		fmt.Fprintf(b, "  replay   %s %3d%%\n",
			d.color(ansiCyan, meter(m.Progress, barW)), pct)
	}

	b.WriteString(d.rule("╰", "╯", w, "", "", ansiDim))
	b.WriteString("\n")
}

// statCell is one "label value" pair on the header's counter line.
type statCell struct {
	label string
	value string
	style string
}

func (d *Dashboard) statLine(cells []statCell) string {
	var b strings.Builder
	b.WriteString(" ")

	for _, c := range cells {
		b.WriteString("  ")
		b.WriteString(d.color(ansiDim, c.label))
		b.WriteString(" ")
		b.WriteString(d.color(c.style, c.value))
	}

	return b.String()
}

// renderSeverityAndRules draws the two most-consulted panels side by side:
// how bad, and what fired.
func (d *Dashboard) renderSeverityAndRules(b *strings.Builder, w int) {
	left := d.severityRows(w/2 - 2)
	right := d.ruleRows(w - w/2 - 2)

	b.WriteString(d.heading2("SEVERITY", "RULES", w))
	b.WriteString("\n")

	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		b.WriteString("  " + padVisible(l, w/2-2) + "  " + r + "\n")
	}
}

// severityRows renders one bar per severity, highest first.
//
// Every severity is listed even at zero. "CRITICAL 0" is information — it says
// the rule set is armed and nothing critical has happened — whereas an absent
// row is ambiguous between that and a display that only shows what has fired.
func (d *Dashboard) severityRows(w int) []string {
	order := []detect.Severity{
		detect.SeverityCritical, detect.SeverityHigh,
		detect.SeverityMedium, detect.SeverityLow,
	}

	var max uint64
	for _, s := range order {
		if d.bySeverity[s] > max {
			max = d.bySeverity[s]
		}
	}

	barW := w - 16
	if barW < 8 {
		barW = 8
	}

	rows := make([]string, 0, len(order))
	for _, s := range order {
		n := d.bySeverity[s]
		style := severityStyle[s]
		if s == detect.SeverityCritical && n == 0 {
			// Do not reverse-video a zero: an empty CRITICAL row
			// styled like a firing one reads as an alert at a glance.
			style = ansiDim
		}

		rows = append(rows, fmt.Sprintf("%s %s %s",
			d.color(style, padVisible(s.String(), 8)),
			d.color(barStyle(s), padVisible(bar(n, max, barW), barW)),
			padVisible(formatCount(n), 5)))
	}

	return rows
}

// barStyle keeps the bars readable without re-using the reversed CRITICAL
// style, which at bar width looks like a solid block of background colour.
func barStyle(s detect.Severity) string {
	switch s {
	case detect.SeverityCritical:
		return ansiRed + ansiBold
	case detect.SeverityHigh:
		return ansiRed
	case detect.SeverityMedium:
		return ansiYellow
	default:
		return ansiCyan
	}
}

// ruleRows lists every enabled rule with its hit count — again including the
// ones at zero, which is what distinguishes "no reverse shells" from "the
// reverse-shell rule is not running".
func (d *Dashboard) ruleRows(w int) []string {
	names := append([]string(nil), d.opts.Rules...)
	if len(names) == 0 {
		for name := range d.byRule {
			names = append(names, name)
		}
		sort.Strings(names)
	}

	// Anything that fired but is not in the enabled list (nothing should
	// be) is still shown rather than silently dropped.
	for name := range d.byRule {
		if !contains(names, name) {
			names = append(names, name)
		}
	}

	rows := make([]string, 0, len(names))
	for _, name := range names {
		n := d.byRule[name]
		style := ansiDim
		if n > 0 {
			style = ansiBlue
		}
		rows = append(rows, fmt.Sprintf("%s %s",
			d.color(style, padVisible(truncate(name, w-7), w-7)),
			padVisible(formatCount(n), 5)))
	}

	return rows
}

// renderTactics shows ATT&CK tactic coverage as a single line of chips.
//
// Tactic *breadth* is the signal the storyline correlator is built on: three
// distinct attacker goals in one tree is the shape of an intrusion, where fifty
// repeats of one goal is the shape of a noisy cron job. Showing which tactics
// have been seen at all makes the attack-chain alert legible when it arrives,
// rather than surprising.
func (d *Dashboard) renderTactics(b *strings.Builder, w int) {
	tactics := []detect.Tactic{
		detect.TacticExecution, detect.TacticPrivEsc, detect.TacticDefenseEvasion,
		detect.TacticCredentialAccess, detect.TacticCommandControl,
	}

	chips := make([]string, 0, len(tactics))
	widths := make([]int, 0, len(tactics))

	for _, t := range tactics {
		n := d.byTactic[t.Name]
		mark, style := "·", ansiDim
		if n > 0 {
			mark, style = "●", ansiYellow+ansiBold
		}
		label := mark + " " + t.Name
		chips = append(chips, d.color(style, label))
		widths = append(widths, len(label))
	}

	b.WriteString(d.heading("ATT&CK TACTICS", w))
	b.WriteString("\n")
	// Wrapped rather than truncated: tactic breadth is the storyline
	// correlator's whole premise, so a narrow terminal must lose a line of
	// height before it loses a tactic.
	b.WriteString(wrapChips(chips, widths, w-4, "   ", "   "))
}

// wrapChips lays chips out in rows no wider than w printable columns.
//
// The widths are passed alongside rather than measured, because the chips may
// already carry ANSI styling by the time they get here.
func wrapChips(chips []string, widths []int, w int, indent, sep string) string {
	var b strings.Builder

	used := 0
	for i, chip := range chips {
		switch {
		case i == 0:
			b.WriteString(indent)
			used = len(indent)
		case used+len(sep)+widths[i] > w:
			b.WriteString("\n" + indent)
			used = len(indent)
		default:
			b.WriteString(sep)
			used += len(sep)
		}

		b.WriteString(chip)
		used += widths[i]
	}

	b.WriteString("\n")
	return b.String()
}

// renderProcesses lists the processes with the most alerts — the triage
// shortlist, and the answer to "what do I kill first".
func (d *Dashboard) renderProcesses(b *strings.Builder, w int) {
	if len(d.byProcess) == 0 {
		return
	}

	type entry struct {
		key procKey
		n   uint64
	}

	list := make([]entry, 0, len(d.byProcess))
	for k, n := range d.byProcess {
		list = append(list, entry{k, n})
	}

	// Count descending, then PID ascending so the order is stable between
	// frames when counts tie — a list that reshuffles every quarter second
	// is unreadable.
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].key.PID < list[j].key.PID
	})

	if len(list) > maxProcRows {
		list = list[:maxProcRows]
	}

	chips := make([]string, 0, len(list))
	widths := make([]int, 0, len(list))

	for _, e := range list {
		label := fmt.Sprintf("%s[%d] ×%d", e.key.Comm, e.key.PID, e.n)
		chips = append(chips, fmt.Sprintf("%s %s",
			d.color(ansiGreen, fmt.Sprintf("%s[%d]", e.key.Comm, e.key.PID)),
			d.color(ansiDim, fmt.Sprintf("×%d", e.n))))
		widths = append(widths, len(label))
	}

	b.WriteString(d.heading("TOP PROCESSES", w))
	b.WriteString("\n")
	b.WriteString(wrapChips(chips, widths, w-4, "   ", "   "))
}

// renderStoryline shows correlation state and, when one exists, the most
// recent attack chain as its timeline.
//
// The timeline is the payload of the whole project: four alerts across four
// PIDs and four rules, put back in order with the tactic each one served. It
// is given permanent screen space because during a demo — and during an
// incident — it is the only panel that answers "what is actually happening".
func (d *Dashboard) renderStoryline(b *strings.Builder, w int, m Metrics, rows int) {
	label := fmt.Sprintf("ATTACK CHAIN   open storylines %d   chains raised %d",
		m.Storylines, m.AttackChains)

	b.WriteString(d.heading(label, w))
	b.WriteString("\n")

	if d.lastChain == nil {
		b.WriteString(d.color(ansiDim, "   no multi-tactic chain yet — alerts are being correlated by process tree"))
		b.WriteString("\n")
		return
	}

	a := d.lastChain

	b.WriteString("   ")
	b.WriteString(d.color(ansiBgRed+ansiWhite+ansiBold, " CRITICAL "))
	b.WriteString(" ")
	b.WriteString(truncate(a.Description, w-16))
	b.WriteString("\n")

	steps := a.Story
	dropped := 0
	if len(steps) > rows {
		// Keep the opening of the story — where the intrusion started is
		// the part that cannot be reconstructed from the latest alert —
		// and account for the rest rather than silently cutting it.
		dropped = len(steps) - (rows - 1)
		steps = steps[:rows-1]
	}

	for i, st := range steps {
		branch := "├─"
		if i == len(steps)-1 && dropped == 0 {
			branch = "└─"
		}

		fmt.Fprintf(b, "   %s %s %s %s %s\n",
			d.color(ansiDim, branch),
			d.color(ansiDim, padVisible(fmt.Sprintf("+%dms", st.OffsetMS), 9)),
			d.color(ansiGreen, padVisible(truncate(fmt.Sprintf("%s[%d]", st.Comm, st.PID), 16), 16)),
			d.color(ansiYellow, padVisible(truncate(st.Tactic, 30), 30)),
			d.color(ansiDim, truncate(st.Summary, maxInt(10, w-66))))
	}

	if dropped > 0 {
		fmt.Fprintf(b, "   %s %s\n",
			d.color(ansiDim, "└─"),
			d.color(ansiDim, fmt.Sprintf("… %d more step(s) — full story in %s", dropped, d.opts.AlertPath)))
	}
}

// renderRecent is the alert feed: newest first, as many as fit.
//
// Newest first, unlike the scrolling console sink, because the eye lands at the
// top of a fixed panel. In a stream the newest line is at the bottom because
// that is where the cursor is; here there is no cursor to follow.
func (d *Dashboard) renderRecent(b *strings.Builder, w, rows int) {

	label := fmt.Sprintf("RECENT ALERTS   %d total", d.total)
	if d.opts.MinSeverity > detect.SeverityLow {
		label += fmt.Sprintf("   showing %s and above", d.opts.MinSeverity)
	}

	b.WriteString(d.heading(label, w))
	b.WriteString("\n")

	if len(d.recent) == 0 {
		b.WriteString(d.color(ansiDim, "   watching — no alerts yet"))
		b.WriteString("\n")
		return
	}

	cols := alertColumns(w)

	shown := 0
	for i := len(d.recent) - 1; i >= 0 && shown < rows; i-- {
		a := d.recent[i]
		if a.Severity < d.opts.MinSeverity {
			continue
		}
		shown++

		proc := truncate(fmt.Sprintf("%s[%d]", a.Comm, a.PID), cols.proc)
		desc := a.Description
		if a.Suppressed > 0 {
			desc = fmt.Sprintf("(+%d folded) %s", a.Suppressed, desc)
		}

		b.WriteString("   ")
		b.WriteString(d.color(ansiDim, a.Timestamp.Format("15:04:05.000")))
		b.WriteString(" ")
		b.WriteString(d.color(severityStyle[a.Severity], padVisible(" "+a.Severity.String()+" ", 10)))
		b.WriteString(" ")
		b.WriteString(d.color(ansiBlue, padVisible(truncate(a.Rule, cols.rule), cols.rule)))
		b.WriteString(" ")
		b.WriteString(d.color(ansiGreen, padVisible(proc, cols.proc)))
		b.WriteString(" ")

		if cols.mitre > 0 {
			b.WriteString(d.color(ansiDim, padVisible(truncate(a.MitreID, cols.mitre), cols.mitre)))
			b.WriteString(" ")
		}

		b.WriteString(truncate(desc, cols.desc))
		b.WriteString("\n")
	}
}

// alertColumns apportions one alert row's columns to the terminal's width.
//
// The row has to fit: a line one column too long wraps, and a wrapped line in a
// repainting display leaves an orphaned half-row that the next frame draws over
// the panel below it. So the description takes whatever is left, and when
// nothing is left the row gives up its columns in order of how much they help
// triage — the ATT&CK id first (it is in the JSONL log and on the chain
// timeline), then width from the rule and process names, and only then the
// description.
func alertColumns(w int) struct{ rule, proc, mitre, desc int } {
	c := struct{ rule, proc, mitre, desc int }{rule: 21, proc: 18, mitre: 10}

	// Fixed overhead: three-space indent, the timestamp, the severity badge
	// and one space after each column.
	const overhead = 3 + 12 + 1 + 10 + 1 + 1 + 1

	avail := func() int {
		n := w - overhead - c.rule - c.proc
		if c.mitre > 0 {
			n -= c.mitre + 1
		}
		return n
	}

	if avail() < minDescCols {
		c.mitre = 0
	}
	for avail() < minDescCols && c.rule > minNameCols {
		c.rule--
	}
	for avail() < minDescCols && c.proc > minNameCols {
		c.proc--
	}

	c.desc = avail()
	if c.desc < 0 {
		c.desc = 0
	}

	return c
}

func (d *Dashboard) renderFooter(b *strings.Builder, w int, m Metrics) {
	left := fmt.Sprintf("alerts → %s", d.opts.AlertPath)

	right := "Ctrl+C to stop"
	if d.opts.Mode == "replay" && m.Progress >= 1 {
		right = "replay complete"
	}

	b.WriteString(d.rule("╰", "╯", w, left, right, ansiDim))
	b.WriteString("\n")
}

// ── Layout helpers ──────────────────────────────────────────────────────────

// rule draws a horizontal divider with text let into it on both ends.
func (d *Dashboard) rule(leftCap, rightCap string, w int, left, right, style string) string {
	var b strings.Builder

	b.WriteString(d.color(ansiDim, leftCap+"─"))

	used := 2
	if left != "" {
		b.WriteString(" " + d.color(style, left) + " ")
		used += visibleLen(left) + 2
	}

	tail := ""
	if right != "" {
		tail = " " + right + " "
	}

	fill := w - used - visibleLen(tail) - 1
	if fill < 1 {
		fill = 1
	}

	b.WriteString(d.color(ansiDim, strings.Repeat("─", fill)))
	if tail != "" {
		b.WriteString(d.color(ansiDim, tail))
	}
	b.WriteString(d.color(ansiDim, rightCap))

	return b.String()
}

// heading labels a panel.
func (d *Dashboard) heading(text string, w int) string {
	pad := w - visibleLen(text) - 3
	if pad < 1 {
		pad = 1
	}
	return "  " + d.color(ansiBold, text) + " " + d.color(ansiDim, strings.Repeat("─", pad))
}

// heading2 labels two side-by-side panels on one line.
//
// The widths are chosen so each label sits exactly above its own column: the
// left heading fills the left column's full width (half), which puts the right
// heading at the same offset as the right column's rows.
func (d *Dashboard) heading2(left, right string, w int) string {
	half := w / 2

	l := "  " + d.color(ansiBold, left) + " " +
		d.color(ansiDim, strings.Repeat("─", maxInt(1, half-visibleLen(left)-3)))
	r := d.color(ansiBold, right) + " " +
		d.color(ansiDim, strings.Repeat("─", maxInt(1, w-half-visibleLen(right)-3)))

	return l + "  " + r
}

func (d *Dashboard) width() int {
	w := d.opts.Width
	if w <= 0 {
		w = terminalWidth(d.w)
	}
	if w < minWidth {
		w = minWidth
	}
	if w > maxWidth {
		w = maxWidth
	}
	return w
}

// color wraps s in an ANSI style, or returns it untouched when colour is off.
//
// Styling after padding, never before, is what keeps the columns aligned:
// padVisible measures printable runes, and an escape sequence is not one.
func (d *Dashboard) color(style, s string) string {
	if !d.opts.Color || style == "" {
		return s
	}
	return style + s + ansiReset
}

func (d *Dashboard) styleIf(cond bool, style string) string {
	if cond {
		return style
	}
	return ""
}

// bar renders a proportional bar, n out of max, in w columns.
func bar(n, max uint64, w int) string {
	if max == 0 || n == 0 {
		return ""
	}

	filled := int(float64(n) / float64(max) * float64(w))
	if filled < 1 {
		// A non-zero count must never render as an empty bar: "0" and
		// "1 out of 40000" have to be distinguishable at a glance.
		filled = 1
	}
	if filled > w {
		filled = w
	}

	return strings.Repeat("█", filled)
}

// meter renders a fractional progress bar, including its unfilled remainder.
func meter(frac float64, w int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}

	filled := int(frac * float64(w))
	return strings.Repeat("█", filled) + strings.Repeat("░", w-filled)
}

// formatCount groups thousands with a thin space, so a six-digit event counter
// can be read without counting digits.
func formatCount(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 4 {
		return s
	}

	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)

	return strings.Join(parts, " ")
}

// formatDuration renders an uptime as mm:ss or h:mm:ss.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}

	total := int(d.Seconds())
	h, m, s := total/3600, (total/60)%60, total%60

	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// visibleLen counts printable runes, skipping ANSI escape sequences.
//
// The state machine matters: a CSI sequence is ESC '[' then parameter bytes
// then one final byte in 0x40–0x7E. Treating the first byte in that range as
// the terminator counts the '[' itself as the end, which makes every styled
// cell measure several columns too wide and skews the whole layout one
// character at a time — the kind of bug that looks like a font problem.
func visibleLen(s string) int {
	const (
		text = iota
		afterESC
		inCSI
		afterIntermediate
	)

	n, state := 0, text

	for _, r := range s {
		switch state {
		case text:
			if r == '\033' {
				state = afterESC
				continue
			}
			n++
		case afterESC:
			switch {
			case r == '[':
				state = inCSI
			case r >= ' ' && r <= '/':
				// An intermediate byte — ESC ( B and friends —
				// which is followed by exactly one final byte.
				state = afterIntermediate
			default:
				// A two-character escape: it ends here.
				state = text
			}
		case afterIntermediate:
			state = text
		case inCSI:
			if r >= '@' && r <= '~' {
				state = text
			}
		}
	}

	return n
}

// padVisible pads s to w printable columns, ignoring any escape sequences in it.
func padVisible(s string, w int) string {
	if n := visibleLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// truncate shortens s to at most w runes, marking the cut with an ellipsis so
// a clipped path is never mistaken for the whole path.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}

	runes := []rune(s)
	if len(runes) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}

	return string(runes[:w-1]) + "…"
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
