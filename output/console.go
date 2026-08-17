package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/praneeth132006/KrnlSentry/detect"
)

// ConsoleSink prints a one-line, colour-coded summary of each alert.
//
// Plain formatted stdout rather than a full-screen TUI (tview and friends).
// That is a considered choice, not a shortcut: a scrolling line-per-alert
// stream can be piped, grepped, redirected to a file and read over SSH, and it
// composes with everything else in a terminal. A full-screen table owns the
// terminal, discards history above the fold, and produces garbage the moment
// anyone pipes it — which is the first thing people do with a monitoring tool.
type ConsoleSink struct {
	mu    sync.Mutex
	w     io.Writer
	color bool

	// minSeverity suppresses anything below it. The JSONL log always gets
	// everything; this only controls what competes for a human's attention.
	minSeverity detect.Severity
}

// ANSI escapes. Written out rather than pulled from a colour library — this is
// the whole of what is needed, and a dependency for six constants is a
// dependency to keep patched forever.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiWhite  = "\033[37m"
	ansiBgRed  = "\033[41m"
)

// severityStyle maps severity to its colour.
//
// CRITICAL gets a reversed background rather than merely a brighter red,
// because red-on-black and bright-red-on-black are nearly indistinguishable in
// a scrolling terminal, and CRITICAL is the one that must not be missed.
var severityStyle = map[detect.Severity]string{
	detect.SeverityLow:      ansiCyan,
	detect.SeverityMedium:   ansiYellow,
	detect.SeverityHigh:     ansiRed + ansiBold,
	detect.SeverityCritical: ansiBgRed + ansiWhite + ansiBold,
}

// NewConsoleSink writes alerts to w.
//
// Colour is enabled only when w is a terminal and NO_COLOR is unset. Both
// checks matter: emitting escape codes into a redirected file makes the file
// unreadable, and NO_COLOR is the cross-tool convention people rely on to turn
// this off. Pass forceColor to override the terminal check for `... | less -R`.
func NewConsoleSink(w io.Writer, forceColor bool, minSeverity detect.Severity) *ConsoleSink {
	return &ConsoleSink{
		w:           w,
		color:       forceColor || shouldColor(w),
		minSeverity: minSeverity,
	}
}

// shouldColor reports whether ANSI output is appropriate for w.
func shouldColor(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}

	f, ok := w.(*os.File)
	if !ok {
		return false
	}

	info, err := f.Stat()
	if err != nil {
		return false
	}

	// A character device is a terminal; a regular file or pipe is not.
	return info.Mode()&os.ModeCharDevice != 0
}

// Write prints one alert.
func (s *ConsoleSink) Write(a *detect.Alert) error {
	if a.Severity < s.minSeverity {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	line := s.format(a)

	if _, err := io.WriteString(s.w, line); err != nil {
		return fmt.Errorf("writing alert to console: %w", err)
	}

	return nil
}

// format builds the display line.
//
// Layout, fixed-width so the eye can scan a column rather than re-read each
// line:
//
//	15:04:05.000  CRITICAL  reverse-shell  bash[4821] uid=1000  T1059
//	              <description>
//	              key=value key=value
//
// The description is on its own line because it is a full sentence; forcing it
// onto the first line would either truncate it or wrap unpredictably at the
// terminal width, and a truncated alert description is a useless alert.
func (s *ConsoleSink) format(a *detect.Alert) string {
	var b strings.Builder

	sev := a.Severity.String()
	proc := fmt.Sprintf("%s[%d]", a.Comm, a.PID)

	if s.color {
		style := severityStyle[a.Severity]

		fmt.Fprintf(&b, "%s%s%s  %s %-8s %s  %s%-22s%s %s%-20s%s %suid=%d%s  %s%s%s\n",
			ansiDim, a.Timestamp.Format("15:04:05.000"), ansiReset,
			style, sev, ansiReset,
			ansiBlue, a.Rule, ansiReset,
			ansiGreen, proc, ansiReset,
			ansiDim, a.UID, ansiReset,
			ansiDim, a.MitreID, ansiReset)

		fmt.Fprintf(&b, "              %s\n", a.Description)

		if args := formatArgs(a.Args); args != "" {
			fmt.Fprintf(&b, "              %s%s%s\n", ansiDim, args, ansiReset)
		}

		return b.String()
	}

	fmt.Fprintf(&b, "%s  %-8s %-22s %-20s uid=%d  %s\n",
		a.Timestamp.Format("15:04:05.000"), sev, a.Rule, proc, a.UID, a.MitreID)

	fmt.Fprintf(&b, "              %s\n", a.Description)

	if args := formatArgs(a.Args); args != "" {
		fmt.Fprintf(&b, "              %s\n", args)
	}

	return b.String()
}

// formatArgs renders the decoded arguments as sorted key=value pairs.
//
// Sorted because Go map iteration is randomised: without this, two identical
// alerts print their arguments in different orders, which makes the output
// impossible to diff and looks like a bug to anyone reading closely.
func formatArgs(args map[string]string) string {
	if len(args) == 0 {
		return ""
	}

	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := args[k]
		// Quote values containing spaces so the pairs stay separable by
		// eye and by a shell-style split.
		if strings.ContainsAny(v, " \t") {
			v = fmt.Sprintf("%q", v)
		}
		parts = append(parts, k+"="+v)
	}

	return strings.Join(parts, " ")
}

// Close is a no-op: the console sink does not own its writer.
//
// Closing os.Stdout here would break every subsequent write in the process,
// including the shutdown summary, so ownership deliberately stays with the
// caller.
func (s *ConsoleSink) Close() error { return nil }

// Banner returns the startup banner shown before monitoring begins.
//
// Worth printing because a security tool that produces no output is ambiguous:
// the operator cannot tell whether nothing is happening or nothing is being
// watched. Stating what was attached and where alerts go resolves that at a
// glance.
func Banner(color bool, version string, rules []string, alertPath string, pidFilter int) string {
	var b strings.Builder

	title := "KrnlSentry"
	if color {
		title = ansiBold + ansiCyan + title + ansiReset
	}

	fmt.Fprintf(&b, "\n%s %s — eBPF syscall monitoring and threat detection\n", title, version)

	sorted := append([]string(nil), rules...)
	sort.Strings(sorted)
	fmt.Fprintf(&b, "  rules   : %s\n", strings.Join(sorted, ", "))
	fmt.Fprintf(&b, "  alerts  : %s\n", alertPath)

	if pidFilter > 0 {
		fmt.Fprintf(&b, "  scope   : PID %d and descendants\n", pidFilter)
	} else {
		fmt.Fprintf(&b, "  scope   : system-wide\n")
	}

	fmt.Fprintf(&b, "  stop    : Ctrl+C\n\n")

	return b.String()
}
