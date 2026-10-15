// Command krnlsentry monitors syscalls with eBPF and alerts on behaviour
// associated with privilege escalation, credential theft, process injection and
// reverse shells.
//
// It must be run with root or with CAP_BPF + CAP_PERFMON, and it runs until
// interrupted:
//
//	sudo krnlsentry
//	sudo krnlsentry --pid 1234 --output /var/log/krnlsentry.jsonl
//	sudo krnlsentry --rules reverse-shell,process-injection --verbose
//	krnlsentry --replay debug.jsonl          # offline, any OS, no privileges
//
// This file is wiring only. Every decision about what is suspicious lives in
// detect/; every decision about how to talk to the kernel lives in ebpfloader/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/praneeth132006/KrnlSentry/detect"
	"github.com/praneeth132006/KrnlSentry/ebpfloader"
	"github.com/praneeth132006/KrnlSentry/events"
	"github.com/praneeth132006/KrnlSentry/output"
)

// Build metadata, injected via -ldflags. See the Makefile.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// eventQueueDepth is how many events may be waiting for the detection engine.
//
// This buffer decouples the ring buffer drain from rule evaluation and alert
// writing. Sizing it is a real trade-off: too small and a momentary stall in
// the detection path backs up into the kernel and drops events there, where we
// lose them silently; too large and a sustained overload is hidden behind
// growing latency until memory becomes a problem. 4096 events is roughly two
// megabytes and absorbs a burst of a few hundred milliseconds.
const eventQueueDepth = 4096

// metricsRefreshInterval is how often the dashboard's counter snapshot is
// retaken on an idle host. Slightly faster than the dashboard repaints, so a
// frame never shows numbers from two refreshes ago.
const metricsRefreshInterval = 200 * time.Millisecond

func main() {
	// All real work is in run() so that deferred cleanup — detaching
	// probes, flushing the alert log — actually executes. os.Exit skips
	// defers, so it is called exactly once, here, after everything has
	// unwound.
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "krnlsentry: %v\n", err)
		os.Exit(1)
	}
}

// config holds parsed command-line options.
type config struct {
	pid           int
	outputPath    string
	rules         string
	verbose       bool
	debugPath     string
	minSeverity   string
	window        time.Duration
	noColor       bool
	forceColor    bool
	ignoreLoop    bool
	ignoreSelf    bool
	statsInterval time.Duration
	showVersion   bool
	listRules     bool

	replayPath     string
	replaySpeed    float64
	dashboard      bool
	dedupWindow    time.Duration
	noStoryline    bool
	chainThreshold int
	chainWindow    time.Duration
}

func parseFlags() (*config, error) {
	cfg := &config{}

	fs := flag.NewFlagSet("krnlsentry", flag.ContinueOnError)

	fs.IntVar(&cfg.pid, "pid", 0,
		"monitor only this PID and its descendants (default: system-wide)")
	fs.StringVar(&cfg.outputPath, "output", "./alerts.jsonl",
		"path to the JSONL alert log")
	fs.StringVar(&cfg.rules, "rules", "",
		"comma-separated subset of rules to enable (default: all)")
	fs.BoolVar(&cfg.verbose, "verbose", false,
		"log every observed syscall to a separate debug log")
	fs.StringVar(&cfg.debugPath, "debug-output", "./debug.jsonl",
		"path to the verbose event log (used with --verbose)")
	fs.StringVar(&cfg.minSeverity, "min-severity", "LOW",
		"minimum severity to print to the console: LOW, MEDIUM, HIGH, CRITICAL")
	fs.DurationVar(&cfg.window, "window", 2*time.Second,
		"time window for the reverse-shell syscall chain")
	fs.BoolVar(&cfg.noColor, "no-color", false,
		"disable coloured console output")
	fs.BoolVar(&cfg.forceColor, "color", false,
		"force coloured output even when stdout is not a terminal")
	fs.BoolVar(&cfg.ignoreLoop, "ignore-loopback", false,
		"suppress reverse-shell alerts for connections to 127.0.0.0/8")
	fs.BoolVar(&cfg.ignoreSelf, "ignore-self-proc", false,
		"suppress sensitive-file alerts when a process reads its own /proc entry")
	fs.DurationVar(&cfg.statsInterval, "stats-interval", 0,
		"periodically log throughput statistics (0 disables)")
	fs.StringVar(&cfg.replayPath, "replay", "",
		"run the rules over a --verbose capture instead of the live kernel (no root, any OS)")
	fs.Float64Var(&cfg.replaySpeed, "replay-speed", 0,
		"pace a --replay against the capture's own clock: 1 = real time, 2 = twice as fast, 0 = as fast as possible")
	fs.BoolVar(&cfg.dashboard, "dashboard", false,
		"replace the scrolling alert stream with a live full-screen dashboard (needs a terminal)")
	fs.DurationVar(&cfg.dedupWindow, "dedup-window", 5*time.Second,
		"fold identical alerts into one per window (0 disables)")
	fs.BoolVar(&cfg.noStoryline, "no-storyline", false,
		"disable cross-process storyline correlation and attack-chain alerts")
	fs.IntVar(&cfg.chainThreshold, "chain-threshold", 3,
		"distinct ATT&CK tactics in one process tree that raise an attack-chain alert")
	fs.DurationVar(&cfg.chainWindow, "chain-window", 10*time.Minute,
		"how long a storyline stays open after its last alert")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version and exit")
	fs.BoolVar(&cfg.listRules, "list-rules", false, "list available detection rules and exit")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "krnlsentry — eBPF syscall monitoring and threat detection\n\n")
		fmt.Fprintf(fs.Output(), "Usage:\n  krnlsentry [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nRules:\n")
		for _, r := range detect.AllRules() {
			fmt.Fprintf(fs.Output(), "  %-24s %s\n", r.Name, r.Description)
		}
		fmt.Fprintf(fs.Output(), "  %-24s %s\n", detect.RuleNameAttackChain,
			"Correlates alerts across a process tree into an ATT&CK kill chain")
		fmt.Fprintf(fs.Output(), "\nLive monitoring requires root, or CAP_BPF and CAP_PERFMON.\n")
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		// flag already printed the problem and the usage text.
		return nil, errSilent
	}

	return cfg, nil
}

// errSilent signals an error already reported to the user, so main should exit
// non-zero without printing anything further.
var errSilent = errors.New("")

func run() error {
	cfg, err := parseFlags()
	if err != nil {
		return err
	}

	if cfg.showVersion {
		fmt.Printf("krnlsentry %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}

	if cfg.listRules {
		printRules()
		return nil
	}

	// In dashboard mode the screen belongs to the display, and an info line
	// written over it leaves a stripe of text that the next repaint only
	// partially covers. Warnings and errors still get through: a torn frame
	// is a much smaller problem than a silently swallowed "events were
	// dropped".
	logLevel := slog.LevelInfo
	if cfg.dashboard {
		logLevel = slog.LevelWarn
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	minSeverity, ok := detect.ParseSeverity(strings.ToUpper(cfg.minSeverity))
	if !ok {
		return fmt.Errorf("invalid --min-severity %q (want LOW, MEDIUM, HIGH or CRITICAL)", cfg.minSeverity)
	}

	// Build the detection engine before touching the kernel. A typo in
	// --rules should fail instantly, not after loading BPF programs and
	// attaching fifteen probes that then have to be torn down.
	engineCfg := detect.DefaultConfig()
	engineCfg.RevShellWindow = cfg.window
	engineCfg.IgnoreLoopback = cfg.ignoreLoop
	engineCfg.IgnoreSelfProc = cfg.ignoreSelf
	engineCfg.DedupWindow = cfg.dedupWindow
	engineCfg.Storyline.Enabled = !cfg.noStoryline
	engineCfg.Storyline.Threshold = cfg.chainThreshold
	engineCfg.Storyline.Window = cfg.chainWindow

	// SIGINT/SIGTERM become context cancellation, so shutdown follows the
	// same path as any other stop and every deferred cleanup runs. Set up
	// before either the replay or the live branch: a paced replay is
	// long-running too, and Ctrl+C on one has to flush the alert log and
	// give the terminal its cursor back rather than killing the process
	// mid-frame.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	replaying := cfg.replayPath != ""
	if replaying {
		// A capture's PIDs belong to another run, possibly on another
		// machine; our own PID colliding with one of them must not hide
		// its events. And /proc describes *this* host now, not the
		// captured one, so lineage comes from the capture alone.
		engineCfg.SelfPID = 0
	} else {
		engineCfg.Storyline.Lookup = lookupProc
	}

	engine, err := detect.NewEngine(engineCfg, splitRules(cfg.rules))
	if err != nil {
		return err
	}

	// Counters live here rather than inside pump/replay because the
	// dashboard reads them while the pipeline writes them.
	var c counters
	metrics := newMetricsSource(&c, engine, replaying)

	// ── Output sinks ────────────────────────────────────────────────────
	jsonl, err := output.NewJSONLSink(cfg.outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := jsonl.Close(); err != nil {
			log.Error("closing alert log", slog.Any("error", err))
		}
	}()

	if cfg.noColor {
		os.Setenv("NO_COLOR", "1")
	}

	// The display is one sink among several, so neither the engine nor the
	// JSONL log knows or cares which one is in use.
	var (
		display output.Sink
		dash    *output.Dashboard
	)

	if cfg.dashboard && !output.DashboardUsable(os.Stdout) && !cfg.forceColor {
		// Refusing rather than emitting escape codes into a pipe: the
		// first thing anyone does with a monitoring tool is redirect it,
		// and a redirected dashboard is an unreadable file. --color is
		// the existing "I know what I am doing" override — it already
		// means exactly this for the console sink — so it also forces
		// the dashboard, which is what recording a demo needs.
		log.Warn("--dashboard needs a terminal; falling back to the scrolling alert stream (--color forces it)")
		cfg.dashboard = false
	}

	if cfg.dashboard && cfg.statsInterval > 0 {
		log.Warn("--stats-interval is redundant with --dashboard; the same counters are on screen continuously")
	}

	if cfg.dashboard {
		dash = output.NewDashboard(os.Stdout, output.DashboardOptions{
			Version:     version,
			Mode:        displayMode(cfg),
			Scope:       scopeLabel(cfg.pid),
			Source:      cfg.replayPath,
			AlertPath:   jsonl.Path(),
			Rules:       enabledRuleNames(engine),
			MinSeverity: minSeverity,
			Color:       !cfg.noColor,
			Metrics:     metrics.snapshot,
		})
		display = dash
	} else {
		display = output.NewConsoleSink(os.Stdout, cfg.forceColor && !cfg.noColor, minSeverity)
	}

	sinks := output.MultiSink{jsonl, display}
	defer func() {
		if err := sinks.Close(); err != nil {
			log.Error("closing sinks", slog.Any("error", err))
		}
	}()

	var debugSink *output.EventSink
	if cfg.verbose {
		debugSink, err = output.NewEventSink(cfg.debugPath)
		if err != nil {
			return err
		}
		defer func() {
			if err := debugSink.Close(); err != nil {
				log.Error("closing debug log", slog.Any("error", err))
			}
		}()
		log.Info("verbose event logging enabled", slog.String("path", debugSink.Path()))
	}

	var filter *pidFilter

	if replaying {
		if cfg.pid > 0 {
			// No /proc walk: the capture's process tree is not this
			// host's. Descendants are learned from the events alone.
			filter = &pidFilter{root: uint32(cfg.pid), tracked: map[uint32]bool{uint32(cfg.pid): true}}
		}
		if dash != nil {
			dash.Start()
			defer func() {
				if err := dash.Close(); err != nil {
					log.Error("closing dashboard", slog.Any("error", err))
				}
			}()
		} else {
			fmt.Print(output.Banner(!cfg.noColor, version, enabledRuleNames(engine), jsonl.Path(), cfg.pid))
			fmt.Printf("  replay  : %s\n\n", cfg.replayPath)
		}

		return replay(ctx, log, cfg.replayPath, engine, sinks, debugSink, filter, metrics, dash, cfg.replaySpeed)
	}

	// ── Kernel side ─────────────────────────────────────────────────────
	collector, err := ebpfloader.New(log)
	if err != nil {
		return err
	}
	// Explicit close rather than only relying on signal handling: an error
	// path below must still detach the probes.
	defer func() {
		if err := collector.Close(); err != nil {
			log.Error("detaching probes", slog.Any("error", err))
		}
	}()

	if cfg.pid > 0 {
		filter = newPIDFilter(uint32(cfg.pid))
		log.Info("PID scope seeded from /proc",
			slog.Int("root", cfg.pid),
			slog.Int("descendants", filter.Len()-1))
	}

	metrics.attachCollector(collector)

	if dash != nil {
		dash.Start()
		defer func() {
			if err := dash.Close(); err != nil {
				log.Error("closing dashboard", slog.Any("error", err))
			}
		}()
	} else {
		fmt.Print(output.Banner(!cfg.noColor, version, enabledRuleNames(engine), jsonl.Path(), cfg.pid))
	}

	return pump(ctx, log, collector, engine, sinks, debugSink, filter, cfg, &c, metrics, dash)
}

// enabledRuleNames lists what will run, for the banner.
func enabledRuleNames(engine *detect.Engine) []string {
	names := make([]string, 0, len(engine.Rules())+1)
	for _, r := range engine.Rules() {
		names = append(names, r.Name)
	}
	if engine.Correlating() {
		names = append(names, detect.RuleNameAttackChain)
	}
	return names
}

// replay drives a recorded capture through exactly the pipeline the live agent
// uses — same scope filter, same engine, same sinks — so its output is what
// the agent would have raised had these rules been running at the time.
//
// That makes three things possible that live tracing cannot do: developing and
// regression-testing rules on a laptop with no eBPF; retro-hunting, i.e. running
// a rule written today over last week's capture; and reproducing a reported
// false positive from the reporter's capture instead of from a description.
func replay(
	ctx context.Context,
	log *slog.Logger,
	path string,
	engine *detect.Engine,
	sinks output.MultiSink,
	debugSink *output.EventSink,
	filter *pidFilter,
	metrics *metricsSource,
	dash *output.Dashboard,
	speed float64,
) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening capture: %w", err)
	}
	// Read-only, so a close error cannot lose data.
	defer func() { _ = f.Close() }()

	// Total size, for progress reporting. A capture with an unknown size
	// (a pipe, a device) simply reports no progress rather than failing.
	var total int64
	if info, statErr := f.Stat(); statErr == nil && info.Mode().IsRegular() {
		total = info.Size()
	}

	counted := &countingReader{r: f}
	c := metrics.counters

	pacer := newPacer(speed)

	err = events.ReadRecords(counted, func(ev events.Event) error {
		if err := pacer.wait(ctx, ev.Timestamp); err != nil {
			return err
		}

		process(log, ev, engine, sinks, debugSink, filter, c)

		// Refreshed from this goroutine, which is the only one that
		// touches the engine, so the dashboard never reads engine state
		// concurrently with rule evaluation.
		metrics.refresh(progressOf(counted.n, total))
		return nil
	})

	// A capture stopped early still reports what it found, so Ctrl+C during
	// a paced replay is a stop rather than a failure.
	interrupted := errors.Is(err, errInterrupted)
	if interrupted {
		err = nil
	} else if err == nil {
		metrics.refresh(1)
	}

	finishDisplay(log, dash)
	printSummary(log, nil, engine, c)

	if interrupted {
		log.Warn("replay interrupted; the capture was not read to the end",
			slog.String("path", path))
		return nil
	}
	if err != nil {
		return fmt.Errorf("replaying %s: %w", path, err)
	}
	if c.observed.Load() == 0 {
		// Most likely an alert log passed where a --verbose capture was
		// expected, or a --pid that matches nothing in the capture.
		log.Warn("no events replayed; is this a --verbose capture, and does --pid match it?",
			slog.String("path", path))
	}
	return nil
}

// countingReader tracks how far through the capture the replay has read, which
// is what the dashboard's progress meter is computed from.
//
// Bytes rather than records: the record count is unknown until the file has
// been read, and counting lines up front would mean reading the capture twice.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// progressOf reports read position as a fraction, or -1 when the total is
// unknown — which the dashboard renders as "no progress bar" rather than as a
// bar stuck at zero.
func progressOf(read, total int64) float64 {
	if total <= 0 {
		return -1
	}
	if read >= total {
		return 1
	}
	return float64(read) / float64(total)
}

// pacer replays a capture against its own clock.
//
// A capture replays in milliseconds by default, which is exactly right for
// tests and retro-hunting: nobody wants to wait out last Tuesday in real time.
// It is wrong for watching, though — every alert and every attack chain in a
// 30-second intrusion lands in the same frame, so the one thing a demo is meant
// to show (a story assembling itself, step by step) is invisible.
//
// --replay-speed divides the capture's own inter-event gaps, measured with the
// kernel's monotonic timestamps, so the sequence unfolds at its original
// rhythm, or a chosen multiple of it. Zero keeps the old behaviour and stays
// the default: pacing is for an audience, not for CI.
type pacer struct {
	speed float64
	// prev is the previous event's monotonic timestamp (nanoseconds since
	// the captured host booted).
	prev  uint64
	first bool
}

func newPacer(speed float64) *pacer {
	return &pacer{speed: speed, first: true}
}

// wait sleeps for the gap between this event and the previous one, or returns
// errInterrupted if the run is cancelled while it waits.
//
// Interruptible because the sleep is the only place a paced replay spends time:
// a plain time.Sleep would leave Ctrl+C unanswered for up to maxPacedGap, with
// a hidden cursor and an unflushed log.
func (p *pacer) wait(ctx context.Context, monotonicNS uint64) error {
	// Checked on every event whatever the pacing, and before the first one:
	// an unpaced replay of a large capture would otherwise be
	// uninterruptible, and a paced one must not sleep through a Ctrl+C.
	select {
	case <-ctx.Done():
		return errInterrupted
	default:
	}

	if p.speed <= 0 {
		return nil
	}

	if p.first {
		p.first, p.prev = false, monotonicNS
		return nil
	}

	// Guard against a non-monotonic capture (hand-edited, or concatenated
	// from two hosts): a backwards step must not sleep for 584 years.
	if monotonicNS > p.prev {
		gap := time.Duration(float64(monotonicNS-p.prev) / p.speed)

		// Cap the wait. A capture with a ten-minute idle gap in the
		// middle would otherwise look exactly like a hung tool.
		if gap > maxPacedGap {
			gap = maxPacedGap
		}

		t := time.NewTimer(gap)
		defer t.Stop()

		select {
		case <-ctx.Done():
			return errInterrupted
		case <-t.C:
		}
	}

	p.prev = monotonicNS
	return nil
}

// errInterrupted stops a replay without making the stop look like a failure.
var errInterrupted = errors.New("interrupted")

// maxPacedGap is the longest pause a paced replay will take between two events.
const maxPacedGap = 2 * time.Second

// metricsSource assembles the figures the dashboard shows but cannot derive
// from the alert stream.
//
// The snapshot is refreshed from the goroutine that owns the pipeline and read
// from the one that paints. That split is deliberate: engine.Stats() and
// Tracker().Len() walk state that rule evaluation is concurrently mutating, so
// the display reads a copy taken at a safe moment rather than the live
// structures.
type metricsSource struct {
	counters  *counters
	engine    *detect.Engine
	replaying bool

	mu        sync.Mutex
	snap      output.Metrics
	collector *ebpfloader.Collector
}

func newMetricsSource(c *counters, engine *detect.Engine, replaying bool) *metricsSource {
	ms := &metricsSource{counters: c, engine: engine, replaying: replaying}
	ms.snap.Progress = -1
	ms.refresh(-1)
	return ms
}

// attachCollector makes kernel-side event and drop counts available once the
// BPF programs are loaded.
func (ms *metricsSource) attachCollector(c *ebpfloader.Collector) {
	ms.mu.Lock()
	ms.collector = c
	ms.mu.Unlock()
}

// refresh recomputes the snapshot. Call it from the pipeline goroutine only.
func (ms *metricsSource) refresh(progress float64) {
	es := ms.engine.Stats()

	m := output.Metrics{
		Observed:     ms.counters.observed.Load(),
		QueueDropped: ms.counters.queueDropped.Load(),
		WriteErrors:  ms.counters.writeErrors.Load(),
		TrackedProcs: ms.engine.Tracker().Len(),
		Storylines:   es.Storylines,
		AttackChains: es.AttackChains,
		Suppressed:   es.Suppressed,
		Progress:     -1,
	}

	if ms.replaying {
		m.Progress = progress
	}

	ms.mu.Lock()
	if ms.collector != nil {
		if s, err := ms.collector.Stats(); err == nil {
			m.KernelEvents, m.KernelDrops = s.Events, s.Dropped
		}
	}
	ms.snap = m
	ms.mu.Unlock()
}

// snapshot returns the last refreshed metrics. Safe to call from any goroutine.
func (ms *metricsSource) snapshot() output.Metrics {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.snap
}

// displayMode labels the header: what this run is watching.
func displayMode(cfg *config) string {
	if cfg.replayPath != "" {
		return "replay"
	}
	return "live"
}

// scopeLabel describes the PID scope in words.
func scopeLabel(pid int) string {
	if pid > 0 {
		return fmt.Sprintf("PID %d + descendants", pid)
	}
	return "system-wide"
}

// counters tracks what happened, for the shutdown summary.
//
// Atomics because the collector goroutine increments queueDropped while the
// main goroutine reads and increments the rest.
type counters struct {
	observed     atomic.Uint64
	alerts       atomic.Uint64
	queueDropped atomic.Uint64
	writeErrors  atomic.Uint64
}

// pump wires the collector to the detection engine and runs until ctx is done.
//
// The two stages run on separate goroutines with a buffered channel between
// them, for the reason given on eventQueueDepth: rule evaluation and file I/O
// must never stall the ring buffer drain.
func pump(
	ctx context.Context,
	log *slog.Logger,
	collector *ebpfloader.Collector,
	engine *detect.Engine,
	sinks output.MultiSink,
	debugSink *output.EventSink,
	filter *pidFilter,
	cfg *config,
	c *counters,
	metrics *metricsSource,
	dash *output.Dashboard,
) error {
	queue := make(chan events.Event, eventQueueDepth)

	collectErr := make(chan error, 1)

	go func() {
		defer close(queue)

		collectErr <- collector.Run(ctx, func(ev events.Event) {
			select {
			case queue <- ev:
			default:
				// The queue is full. Dropping here rather than
				// blocking is the right call: blocking would
				// stall the ring buffer reader and push the loss
				// into the kernel, where it is invisible.
				// Dropping here is at least counted and
				// reported.
				c.queueDropped.Add(1)
			}
		})
	}()

	// Keeps the dashboard's counters current while the host is quiet: with
	// no events arriving, nothing else would ever refresh the snapshot and
	// the uptime would be the only thing moving on screen.
	refresh := time.NewTicker(metricsRefreshInterval)
	defer refresh.Stop()

	var statsTicker *time.Ticker
	var statsC <-chan time.Time
	if cfg.statsInterval > 0 {
		statsTicker = time.NewTicker(cfg.statsInterval)
		defer statsTicker.Stop()
		statsC = statsTicker.C
	}

	for {
		select {
		case ev, ok := <-queue:
			if !ok {
				// Collector finished; report how it went and
				// print the summary.
				err := <-collectErr
				metrics.refresh(-1)
				finishDisplay(log, dash)
				printSummary(log, collector, engine, c)
				return err
			}

			process(log, ev, engine, sinks, debugSink, filter, c)

		case <-refresh.C:
			metrics.refresh(-1)

		case <-statsC:
			logStats(log, collector, engine, c)
		}
	}
}

// process handles one event: scope filter, optional verbose logging, rule
// evaluation, alert output.
func process(
	log *slog.Logger,
	ev events.Event,
	engine *detect.Engine,
	sinks output.MultiSink,
	debugSink *output.EventSink,
	filter *pidFilter,
	c *counters,
) {
	if filter != nil && !filter.Allow(ev) {
		return
	}

	c.observed.Add(1)

	if debugSink != nil {
		if err := debugSink.WriteEvent(ev); err != nil {
			// Log once per failure rather than aborting: losing the
			// debug log is not a reason to stop detecting.
			c.writeErrors.Add(1)
			log.Error("writing debug event", slog.Any("error", err))
		}
	}

	for _, alert := range engine.Evaluate(ev) {
		c.alerts.Add(1)

		if err := sinks.Write(alert); err != nil {
			c.writeErrors.Add(1)
			log.Error("writing alert", slog.Any("error", err))
		}
	}
}

// finishDisplay paints the dashboard's last frame and releases the terminal
// before the shutdown summary is written.
//
// Ordering, not tidiness: the dashboard repaints from the cursor home position
// and erases below itself, so a summary printed first would be wiped by the
// final frame. Closing here leaves the run's totals on screen with the summary
// underneath them, which is the order they were produced in and the order
// somebody reading back wants them. Close is idempotent, so the deferred close
// on the error paths is still safe.
func finishDisplay(log *slog.Logger, dash *output.Dashboard) {
	if dash == nil {
		return
	}
	if err := dash.Close(); err != nil {
		log.Error("closing dashboard", slog.Any("error", err))
	}
}

// logStats emits a periodic throughput line.
func logStats(log *slog.Logger, collector *ebpfloader.Collector, engine *detect.Engine, c *counters) {
	attrs := []any{
		slog.Uint64("observed", c.observed.Load()),
		slog.Uint64("alerts", c.alerts.Load()),
		slog.Uint64("queue_dropped", c.queueDropped.Load()),
		slog.Int("tracked_processes", engine.Tracker().Len()),
		slog.Int("open_storylines", engine.Stats().Storylines),
		slog.Uint64("attack_chains", engine.Stats().AttackChains),
	}

	if s, err := collector.Stats(); err == nil {
		attrs = append(attrs,
			slog.Uint64("kernel_events", s.Events),
			slog.Uint64("kernel_dropped", s.Dropped))
	}

	log.Info("stats", attrs...)
}

// printSummary reports the run's totals on shutdown.
//
// The drop counts are the important part. A monitoring tool that quietly
// discarded events looks identical to one that saw nothing suspicious, so any
// non-zero drop count is surfaced as a warning with the reason and the fix.
func printSummary(log *slog.Logger, collector *ebpfloader.Collector, engine *detect.Engine, c *counters) {
	var (
		kernelStats ebpfloader.Stats
		statsErr    = errors.New("no collector")
	)
	if collector != nil {
		kernelStats, statsErr = collector.Stats()
	}
	es := engine.Stats()

	fmt.Fprintf(os.Stderr, "\n── summary ─────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  events observed : %d\n", c.observed.Load())
	fmt.Fprintf(os.Stderr, "  alerts raised   : %d\n", c.alerts.Load())
	fmt.Fprintf(os.Stderr, "  rules enabled   : %d\n", len(engine.Rules()))

	if es.Suppressed > 0 {
		fmt.Fprintf(os.Stderr, "  alerts folded   : %d  (duplicates within --dedup-window)\n", es.Suppressed)
	}
	if engine.Correlating() {
		fmt.Fprintf(os.Stderr, "  attack chains   : %d\n", es.AttackChains)
	}

	if statsErr == nil {
		fmt.Fprintf(os.Stderr, "  kernel events   : %d\n", kernelStats.Events)
		if kernelStats.Dropped > 0 {
			fmt.Fprintf(os.Stderr, "  kernel drops    : %d  (ring buffer full)\n", kernelStats.Dropped)
		}
	}

	if d := c.queueDropped.Load(); d > 0 {
		fmt.Fprintf(os.Stderr, "  queue drops     : %d  (detection engine fell behind)\n", d)
	}

	if e := c.writeErrors.Load(); e > 0 {
		fmt.Fprintf(os.Stderr, "  write errors    : %d\n", e)
	}

	fmt.Fprintf(os.Stderr, "────────────────────────────────────────\n")

	totalDropped := c.queueDropped.Load()
	if statsErr == nil {
		totalDropped += kernelStats.Dropped
	}

	if totalDropped > 0 {
		log.Warn("events were dropped; this run's coverage is incomplete",
			slog.Uint64("dropped", totalDropped),
			slog.String("mitigation", "reduce scope with --pid, or disable --verbose"))
	}
}

// printRules lists the rule registry with the ATT&CK techniques each can report.
func printRules() {
	fmt.Println("Available detection rules:")
	fmt.Println()

	for _, r := range detect.AllRules() {
		fmt.Printf("  %s\n", r.Name)
		fmt.Printf("      %s\n", r.Description)

		for _, t := range r.Techniques {
			fmt.Printf("      %-12s %s\n", t.ID, t.Name)
		}
		fmt.Println()
	}

	fmt.Printf("  %s\n", detect.RuleNameAttackChain)
	fmt.Println("      Correlates alerts from one process tree; raised when they span")
	fmt.Println("      --chain-threshold distinct ATT&CK tactics (disable with --no-storyline)")
	for _, t := range []detect.Tactic{
		detect.TacticExecution, detect.TacticPrivEsc, detect.TacticDefenseEvasion,
		detect.TacticCredentialAccess, detect.TacticCommandControl,
	} {
		fmt.Printf("      %-12s %s\n", t.ID, t.Name)
	}
	fmt.Println()
}

// splitRules turns the --rules value into a slice, tolerating spaces and
// trailing commas. An empty result means "all rules", which NewEngine handles.
func splitRules(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}

	return out
}
