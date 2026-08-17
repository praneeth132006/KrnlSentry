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
//
// This file is wiring only. Every decision about what is suspicious lives in
// detect/; every decision about how to talk to the kernel lives in ebpfloader/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
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
		fmt.Fprintf(fs.Output(), "\nRequires root, or CAP_BPF and CAP_PERFMON.\n")
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

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
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

	engine, err := detect.NewEngine(engineCfg, splitRules(cfg.rules))
	if err != nil {
		return err
	}

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

	console := output.NewConsoleSink(os.Stdout, cfg.forceColor && !cfg.noColor, minSeverity)
	if cfg.noColor {
		console = output.NewConsoleSink(os.Stdout, false, minSeverity)
		os.Setenv("NO_COLOR", "1")
	}

	sinks := output.MultiSink{jsonl, console}
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

	// ── Signals ─────────────────────────────────────────────────────────
	// NotifyContext converts SIGINT/SIGTERM into context cancellation, so
	// shutdown follows the same path as any other stop and every deferred
	// cleanup above runs. This is the "must clean up on SIGINT/SIGTERM"
	// requirement, implemented once rather than in a signal handler that
	// would have to duplicate the teardown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var filter *pidFilter
	if cfg.pid > 0 {
		filter = newPIDFilter(uint32(cfg.pid))
		log.Info("PID scope seeded from /proc",
			slog.Int("root", cfg.pid),
			slog.Int("descendants", filter.Len()-1))
	}

	ruleNames := make([]string, 0, len(engine.Rules()))
	for _, r := range engine.Rules() {
		ruleNames = append(ruleNames, r.Name)
	}
	fmt.Print(output.Banner(!cfg.noColor, version, ruleNames, jsonl.Path(), cfg.pid))

	return pump(ctx, log, collector, engine, sinks, debugSink, filter, cfg)
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
) error {
	queue := make(chan events.Event, eventQueueDepth)
	var c counters

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
				printSummary(log, collector, engine, &c)
				return err
			}

			process(log, ev, engine, sinks, debugSink, filter, &c)

		case <-statsC:
			logStats(log, collector, engine, &c)
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

// logStats emits a periodic throughput line.
func logStats(log *slog.Logger, collector *ebpfloader.Collector, engine *detect.Engine, c *counters) {
	attrs := []any{
		slog.Uint64("observed", c.observed.Load()),
		slog.Uint64("alerts", c.alerts.Load()),
		slog.Uint64("queue_dropped", c.queueDropped.Load()),
		slog.Int("tracked_processes", engine.Tracker().Len()),
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
	kernelStats, statsErr := collector.Stats()

	fmt.Fprintf(os.Stderr, "\n── summary ─────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  events observed : %d\n", c.observed.Load())
	fmt.Fprintf(os.Stderr, "  alerts raised   : %d\n", c.alerts.Load())

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

	_ = engine
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
