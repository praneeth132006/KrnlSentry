// Package ebpfloader owns every interaction with the kernel: loading the
// compiled BPF object, attaching it to tracepoints, draining the ring buffer,
// and tearing all of it down again.
//
// It is the only package in the project that imports cilium/ebpf. Everything it
// hands outward is an events.Event — a plain struct with no kernel handles in
// it — which is what lets the detection engine be tested without root, without
// a kernel, and without eBPF support in CI.
//
// Nothing here decides what is suspicious. If you find yourself adding a
// filename or a uid comparison to this file, it belongs in detect/ instead.
package ebpfloader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/praneeth132006/KrnlSentry/events"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpfloader -output-dir . -target amd64,arm64 -type event -type config -cc clang -cflags "-O2 -g -Wall -Werror -I../bpf" KrnlSentry ../bpf/krnlsentry.bpf.c

// Statistics slot indices, mirroring `enum ks_stat` in bpf/event.h.
const (
	statEvents  uint32 = 0
	statDropped uint32 = 1
)

// Stats reports what the kernel side has seen.
//
// Dropped is the number the operator actually needs: it counts events the
// kernel could not enqueue because userspace was not draining fast enough.
// Those events are gone — not delayed — so a non-zero value means this tool's
// output is incomplete for that window. Reporting it is the difference between
// a monitor that is honest about its blind spots and one that quietly
// under-reports.
type Stats struct {
	Events  uint64
	Dropped uint64
}

// Collector loads the BPF programs, attaches them, and streams decoded events.
//
// The zero value is not usable; construct one with New.
type Collector struct {
	objs  KrnlSentryObjects
	links []link.Link

	reader *ringbuf.Reader

	// bootTime converts the kernel's monotonic timestamps into wall clock.
	// Sampled once at startup rather than per event, both because it is
	// relatively expensive and because a per-event sample would make two
	// events with the same kernel timestamp resolve to different wall times.
	bootTime time.Time

	log *slog.Logger
}

// tracepoint describes one probe and where it attaches.
//
// The group and name are the directory path under
// /sys/kernel/tracing/events/, and the field selects the matching program from
// the generated objects struct. Keeping this as data rather than fifteen
// near-identical attach calls means adding a probe is one line, and the attach
// loop's error handling is written once.
type tracepoint struct {
	group   string
	name    string
	program func(*KrnlSentryObjects) *ebpf.Program
}

// tracepoints is the full attach list.
//
// Order matters only for the error message a user sees when one fails, so the
// entries are grouped by the detection they serve rather than alphabetically.
var tracepoints = []tracepoint{
	// Execution — SUID checks and the tail of the reverse-shell chain.
	{"syscalls", "sys_enter_execve", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceExecve }},
	{"syscalls", "sys_enter_execveat", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceExecveat }},

	// File access — sensitive path rules.
	{"syscalls", "sys_enter_openat", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceOpenat }},

	// Credential changes — privilege escalation rules.
	{"syscalls", "sys_enter_setuid", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceSetuid }},
	{"syscalls", "sys_enter_setgid", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceSetgid }},
	{"syscalls", "sys_enter_setresuid", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceSetresuid }},
	{"syscalls", "sys_enter_setresgid", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceSetresgid }},
	{"syscalls", "sys_enter_capset", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceCapset }},

	// Process injection.
	{"syscalls", "sys_enter_ptrace", func(o *KrnlSentryObjects) *ebpf.Program { return o.TracePtrace }},

	// Reverse-shell chain.
	{"syscalls", "sys_enter_socket", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceSocket }},
	{"syscalls", "sys_exit_socket", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceSocketExit }},
	{"syscalls", "sys_enter_connect", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceConnect }},
	{"syscalls", "sys_exit_connect", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceConnectExit }},
	{"syscalls", "sys_enter_dup2", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceDup2 }},
	{"syscalls", "sys_enter_dup3", func(o *KrnlSentryObjects) *ebpf.Program { return o.TraceDup3 }},
}

// optionalTracepoints are probes whose absence is tolerated.
//
// sys_enter_dup2 genuinely does not exist on arm64 — the architecture has no
// dup2 syscall, only dup3 — so attaching it fails with ENOENT on every ARM
// machine. Treating that as fatal would make the tool refuse to start on an
// Apple Silicon dev box for a reason that has no security consequence
// (dup3 covers the same behaviour). Everything else must attach or we fail
// loudly: a security tool that silently monitors less than it claims to is
// worse than one that refuses to run.
var optionalTracepoints = map[string]bool{
	"sys_enter_dup2": true,
}

// New loads the embedded BPF object, attaches every probe, and opens the ring
// buffer. On any failure it unwinds whatever it already attached, so a partial
// failure never leaves probes stranded in the kernel.
func New(log *slog.Logger) (c *Collector, err error) {
	if log == nil {
		log = slog.Default()
	}

	// BPF maps are charged against RLIMIT_MEMLOCK on kernels before 5.11.
	// The default limit (often 64 KiB) is smaller than our 256 KiB ring
	// buffer, so without this the load fails with a EPERM that looks like a
	// permissions problem and sends people hunting in the wrong place.
	// On 5.11+ this is a no-op because memory is charged to the cgroup.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising RLIMIT_MEMLOCK: %w", err)
	}

	col := &Collector{log: log}

	// From here on, any error must undo the work already done.
	defer func() {
		if err != nil {
			col.Close()
		}
	}()

	if err := LoadKrnlSentryObjects(&col.objs, nil); err != nil {
		return nil, describeLoadError(err)
	}

	if err := col.writeConfig(); err != nil {
		return nil, err
	}

	if err := col.attachAll(); err != nil {
		return nil, err
	}

	col.reader, err = ringbuf.NewReader(col.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("opening ring buffer reader: %w", err)
	}

	col.bootTime, err = bootTime()
	if err != nil {
		return nil, fmt.Errorf("determining boot time: %w", err)
	}

	log.Info("eBPF probes attached",
		slog.Int("tracepoints", len(col.links)),
		slog.String("ringbuf", "256 KiB"))

	return col, nil
}

// writeConfig publishes our own TGID to the kernel so the probes can ignore
// our syscalls.
//
// This must happen before attach, not after. Between attaching and writing the
// config there would be a window in which our own file writes generate events
// that we then log, generating more events — the feedback loop described in
// krnlsentry.bpf.c. Doing it first closes the window entirely.
func (c *Collector) writeConfig() error {
	cfg := KrnlSentryConfig{SelfTgid: uint32(os.Getpid())}

	if err := c.objs.ConfigMap.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("writing self-pid filter to config map: %w", err)
	}

	return nil
}

// attachAll links every program to its tracepoint.
func (c *Collector) attachAll() error {
	for _, tp := range tracepoints {
		prog := tp.program(&c.objs)
		if prog == nil {
			return fmt.Errorf("program for %s/%s missing from compiled object", tp.group, tp.name)
		}

		l, err := link.Tracepoint(tp.group, tp.name, prog, nil)
		if err != nil {
			if optionalTracepoints[tp.name] && errors.Is(err, os.ErrNotExist) {
				c.log.Debug("optional tracepoint not present on this kernel",
					slog.String("tracepoint", tp.group+"/"+tp.name))
				continue
			}
			return fmt.Errorf("attaching %s/%s: %w", tp.group, tp.name, err)
		}

		c.links = append(c.links, l)
	}

	if len(c.links) == 0 {
		return errors.New("no tracepoints attached; refusing to run blind")
	}

	return nil
}

// Run drains the ring buffer until ctx is cancelled, invoking handler for each
// decoded event.
//
// handler is called on this goroutine, so it must be fast. Anything that can
// block — writing a log file, an alert webhook — belongs behind a buffered
// channel in the caller, because a slow handler here means a full ring buffer
// and dropped events.
func (c *Collector) Run(ctx context.Context, handler func(events.Event)) error {
	// ringbuf.Reader.Read blocks in the kernel and does not watch a
	// context. Closing the reader is what unblocks it, so a small goroutine
	// translates cancellation into a close.
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			// Errors here are not actionable: the only reason Close
			// fails is that the reader is already closed, which is
			// exactly the state we want.
			_ = c.reader.Close()
		case <-done:
		}
	}()

	for {
		record, err := c.reader.Read()
		if err != nil {
			// A closed reader is the normal shutdown path, not a
			// failure — distinguish it so Ctrl+C does not print an
			// error.
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading from ring buffer: %w", err)
		}

		raw, err := parseRecord(record.RawSample)
		if err != nil {
			// One malformed record must not kill the agent. This
			// would mean a kernel/userspace layout mismatch, which
			// is worth shouting about but is not a reason to stop
			// monitoring.
			c.log.Warn("discarding malformed event", slog.Any("error", err))
			continue
		}

		handler(events.Decode(raw, c.bootTime))
	}
}

// Stats sums the per-CPU counters maintained by the BPF programs.
func (c *Collector) Stats() (Stats, error) {
	var s Stats

	events, err := c.sumPerCPU(statEvents)
	if err != nil {
		return s, fmt.Errorf("reading event counter: %w", err)
	}

	dropped, err := c.sumPerCPU(statDropped)
	if err != nil {
		return s, fmt.Errorf("reading drop counter: %w", err)
	}

	s.Events = events
	s.Dropped = dropped

	return s, nil
}

// sumPerCPU reads one slot of the per-CPU stats array and totals it.
// A per-CPU map lookup returns one value per possible CPU, not per online CPU.
func (c *Collector) sumPerCPU(slot uint32) (uint64, error) {
	var perCPU []uint64

	if err := c.objs.StatsMap.Lookup(slot, &perCPU); err != nil {
		return 0, err
	}

	var total uint64
	for _, v := range perCPU {
		total += v
	}

	return total, nil
}

// Close detaches every probe and releases all kernel resources.
//
// Safe to call more than once and safe to call on a partially constructed
// Collector, which is what makes the unwind-on-error path in New correct.
// Errors are collected rather than returned on the first failure: a probe that
// will not detach must not prevent the other fourteen from being cleaned up.
func (c *Collector) Close() error {
	var errs []error

	if c.reader != nil {
		if err := c.reader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing ring buffer: %w", err))
		}
		c.reader = nil
	}

	// Detach in reverse attach order, so the kernel tears down the most
	// recently added links first.
	for i := len(c.links) - 1; i >= 0; i-- {
		if err := c.links[i].Close(); err != nil {
			errs = append(errs, fmt.Errorf("detaching probe: %w", err))
		}
	}
	c.links = nil

	if err := c.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing BPF objects: %w", err))
	}

	return errors.Join(errs...)
}

// bootTime returns the wall-clock instant the system booted.
//
// Derived by subtracting CLOCK_MONOTONIC from the current wall clock, because
// that is precisely the clock bpf_ktime_get_ns() reads. Using CLOCK_BOOTTIME
// instead would be subtly wrong: it includes time spent suspended, so on a
// laptop that has been closed and reopened every timestamp would be off by the
// length of the suspend.
func bootTime() (time.Time, error) {
	var ts unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Time{}, fmt.Errorf("clock_gettime(CLOCK_MONOTONIC): %w", err)
	}

	uptime := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)

	return time.Now().Add(-uptime), nil
}

// describeLoadError turns the kernel's terse load failures into something a
// user can act on.
//
// This is worth the effort because the failure modes are common and the raw
// errors are actively misleading: a missing-BTF kernel reports a verifier
// error, and insufficient privileges report EPERM from deep inside the library
// with no hint that sudo is the answer.
func describeLoadError(err error) error {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w\n\nloading eBPF requires privileges. Run with sudo, or grant "+
			"CAP_BPF and CAP_PERFMON (CAP_SYS_ADMIN on kernels before 5.8)", err)

	case errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EINVAL):
		return fmt.Errorf("%w\n\nthe kernel rejected the program. KrnlSentry needs kernel 5.8+ "+
			"with CONFIG_DEBUG_INFO_BTF=y and CONFIG_BPF_SYSCALL=y. Check: "+
			"ls -l /sys/kernel/btf/vmlinux", err)

	default:
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// The verifier log is long and the useful part is at the
			// end, but truncating it hides the actual rejection.
			// Print it in full; this is a developer-facing failure.
			return fmt.Errorf("BPF verifier rejected the program: %+v", ve)
		}
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
}
