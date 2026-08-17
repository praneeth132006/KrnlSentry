package detect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Rule 5.4 — Reverse Shell Syscall Chain.
//
// This is the rule the whole per-process tracker exists for, and the one that
// justifies the architecture. Consider the four syscalls involved:
//
//	socket()   — every network client does this
//	connect()  — every network client does this
//	dup2()     — every shell doing redirection does this
//	execve()   — every process launch does this
//
// Not one of them is suspicious. Alerting on any of them individually would
// produce thousands of events an hour and be switched off the same day. What is
// suspicious is the *specific ordering* within a short window inside a single
// process: open a socket, dial out, staple that socket onto stdin/stdout/stderr,
// then exec a shell. At that point the process's terminal is a remote attacker's
// terminal.
//
// This is the difference between a syscall logger and a detection tool, and it
// is why events must arrive in order — see the ring-buffer rationale in
// krnlsentry.bpf.c. With a per-CPU perf buffer the ordering guarantee this rule
// depends on would not exist.

var ruleReverseShell = Rule{
	Name:        RuleNameReverseShell,
	Description: "socket → connect → dup2(std fds) → execve sequence within one process",
	Techniques: []Technique{
		TechCommandInterpreter,
		TechAppLayerProtocol,
	},
	Eval: evalReverseShell,
}

// minRedirectedFDs is how many of stdin/stdout/stderr must be redirected before
// the chain counts.
//
// Two, not three. The canonical payload redirects all three, but plenty of real
// ones wire up only stdin and stdout — stderr is often left alone, and some
// redirect it with 2>&1 in the shell rather than a dup2. Requiring three would
// miss those; requiring one would match ordinary programs that redirect a single
// stream to a file. Two is the point where the pattern stops being ordinary.
const minRedirectedFDs = 2

func evalReverseShell(c Context) *Alert {
	ev := c.Event

	// The chain is judged at its final step. Evaluating on any earlier
	// syscall would either fire before the pattern is complete or fire
	// repeatedly as each subsequent piece arrives.
	if ev.IsExit || !ev.SyscallID.IsExecution() {
		return nil
	}

	window := c.Config.RevShellWindow
	hist := c.History.Within(ev.Timestamp, window)
	if len(hist) == 0 {
		return nil
	}

	chain, ok := findChain(hist)
	if !ok {
		return nil
	}

	if c.Config.IgnoreLoopback && isLoopback(chain.destIP) {
		return nil
	}

	// Present the evidence, not just the verdict. An analyst who cannot see
	// which descriptors were redirected and how long the chain took has to
	// go back to the raw log to decide whether to believe the alert.
	fds := make([]string, 0, len(chain.redirected))
	for fd := range chain.redirected {
		if name := events.StdFdName(fd); name != "" {
			fds = append(fds, name)
		} else {
			fds = append(fds, strconv.FormatInt(fd, 10))
		}
	}
	sort.Strings(fds)

	ev.Args["chain_redirected"] = strings.Join(fds, ",")
	ev.Args["chain_duration_ms"] = strconv.FormatInt(
		int64(time.Duration(ev.Timestamp-chain.startTS)/time.Millisecond), 10)
	ev.Args["chain_socket_fd_confirmed"] = strconv.FormatBool(chain.fdConfirmed)

	dest := chain.destination()
	if dest != "" {
		ev.Args["chain_dest"] = dest
	}

	return newAlert(ev, RuleNameReverseShell, TechCommandInterpreter, SeverityCritical,
		fmt.Sprintf("Process %s completed socket → connect%s → dup2(%s) → execve(%q) in %sms — reverse shell pattern",
			procLabel(ev),
			destSuffix(dest),
			strings.Join(fds, ","),
			ev.Path,
			ev.Args["chain_duration_ms"]))
}

// chainMatch records what was found, so the alert can describe it.
type chainMatch struct {
	startTS    uint64
	destIP     string
	destPort   uint16
	redirected map[int64]bool

	// fdConfirmed reports whether a dup2 was seen duplicating the exact
	// descriptor that socket() returned. When true the match is materially
	// stronger — it rules out the coincidence of a program that happens to
	// open a socket and, separately, redirect a file onto stdout.
	fdConfirmed bool
}

func (c chainMatch) destination() string {
	if c.destIP == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.destIP, c.destPort)
}

func destSuffix(dest string) string {
	if dest == "" {
		return ""
	}
	return " to " + dest
}

// findChain looks for socket → connect → dup2×N in a process's recent history.
//
// The search is ordered rather than a bag of "did all of these happen":
// requiring connect to follow socket, and the redirections to follow connect,
// is what distinguishes the attack pattern from a program that coincidentally
// performed the same four syscalls in an innocuous arrangement.
//
// The first socket and the first subsequent connect anchor the chain. Taking
// the first rather than the last is deliberate: a payload that opens its socket
// early and execs late is still the same chain, and anchoring on the latest
// socket would break on any process that opened a second, unrelated one.
func findChain(hist []HistoryEntry) (chainMatch, bool) {
	var (
		match      chainMatch
		socketIdx  = -1
		connectIdx = -1
		socketFD   = int64(-1)
	)

	for i, e := range hist {
		switch {
		case e.Syscall == events.SysSocket && !e.IsExit:
			if socketIdx < 0 {
				socketIdx = i
				match.startTS = e.Timestamp
			}

		case e.Syscall == events.SysSocket && e.IsExit:
			// The return probe carries the allocated descriptor.
			// Negative means the call failed, in which case there is
			// no socket to dup and nothing to confirm.
			if socketIdx >= 0 && socketFD < 0 && e.Ret >= 0 {
				socketFD = e.Ret
			}

		case e.Syscall == events.SysConnect && !e.IsExit:
			if socketIdx >= 0 && connectIdx < 0 {
				connectIdx = i
				match.destIP = e.DestIP
				match.destPort = e.DestPort
			}
		}
	}

	if socketIdx < 0 || connectIdx < 0 {
		return chainMatch{}, false
	}

	match.redirected = make(map[int64]bool, 3)

	for _, e := range hist[connectIdx+1:] {
		if !e.Syscall.IsDup() || e.IsExit {
			continue
		}

		// Arg1 is newfd — the descriptor being *replaced*. Redirecting
		// something onto fd 7 is unremarkable; redirecting onto 0, 1 or
		// 2 is the process handing its standard streams somewhere else.
		if events.StdFdName(e.Arg1) == "" {
			continue
		}

		match.redirected[e.Arg1] = true

		if socketFD >= 0 && e.Arg0 == socketFD {
			match.fdConfirmed = true
		}
	}

	if len(match.redirected) < minRedirectedFDs {
		return chainMatch{}, false
	}

	return match, true
}

// isLoopback reports whether an address is on the local machine.
func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1"
}
