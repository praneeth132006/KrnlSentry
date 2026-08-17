package detect

import (
	"fmt"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Rule 5.3 — Process Injection via ptrace.
//
// ptrace() is how one process reads and writes another's memory and registers.
// Debuggers use it legitimately; so does every ptrace-based code injector, and
// the syscalls are identical. The only thing separating the two is who is
// making the call.
//
// ON THE ALLOWLIST, WHICH IS THE WEAK PART
// ────────────────────────────────────────
// Exempting processes by `comm` is spoofable in the most trivial way available:
// comm is just the first 15 bytes of the executable name, and anything that
// wants to bypass this rule copies itself to /tmp/gdb and runs that. There is no
// clever fix at this layer — comm is what the kernel gives us cheaply.
//
// A real product would verify the *binary* rather than its name: check the
// executable's inode against a known path, or better, validate a code signature
// or an IMA/EVM measurement. That means resolving /proc/<pid>/exe and hashing
// it, which is a filesystem round trip per ptrace call and a different design
// than this MVP.
//
// The allowlist is kept anyway because without it the rule is unusable on a
// developer machine — a single debugging session produces thousands of ptrace
// calls. It buys usability, not security, and this comment exists so nobody
// mistakes it for the latter.

var rulePtraceInjection = Rule{
	Name:        RuleNameProcessInjection,
	Description: "ptrace used to attach to or write into another process",
	Techniques: []Technique{
		TechProcessInjection,
		TechPtraceInjection,
	},
	Eval: evalPtraceInjection,
}

// injectionRequests are the ptrace operations that take control of, or write
// into, another process. Read-only operations (PEEK*, GETREGS) are deliberately
// excluded: reading another process's memory is reconnaissance worth far less
// than the write primitives, and including them makes the rule noisy enough to
// be muted.
//
// Both register-setting spellings are present. PTRACE_SETREGS (13) does not
// exist on arm64 — that architecture uses PTRACE_SETREGSET (0x4205) instead —
// so a rule listing only the former would never fire on an ARM host. That is
// the kind of gap that goes unnoticed precisely because it fails silently.
var injectionRequests = map[int64]string{
	events.PtraceAttach:    "attaching to another process",
	events.PtraceSeize:     "seizing another process",
	events.PtracePoketext:  "writing to another process's text segment",
	events.PtracePokedata:  "writing to another process's data segment",
	events.PtracePokeuser:  "writing to another process's user area",
	events.PtraceSetregs:   "overwriting another process's registers",
	events.PtraceSetregset: "overwriting another process's registers",
	events.PtraceSetfpregs: "overwriting another process's FP registers",
}

func evalPtraceInjection(c Context) *Alert {
	ev := c.Event

	if ev.IsExit || ev.SyscallID != events.SysPtrace {
		return nil
	}

	action, interesting := injectionRequests[ev.Arg0]
	if !interesting {
		return nil
	}

	// PTRACE_TRACEME is how a child volunteers to be traced by its own
	// parent; it is not in the map above, but guard the general case of a
	// process targeting itself as well. Self-ptrace is an anti-debugging
	// technique, not injection into someone else.
	if ev.Arg1 == int64(ev.PID) {
		return nil
	}

	if isKnownDebugger(ev.Comm, c.Config.DebuggerComms) {
		return nil
	}

	ev.Args["action"] = action

	return newAlert(ev, RuleNameProcessInjection, TechPtraceInjection, SeverityHigh,
		fmt.Sprintf("Process %s called ptrace(%s) against PID %d — %s, possible process injection",
			procLabel(ev), events.PtraceRequestName(ev.Arg0), ev.Arg1, action))
}

// isKnownDebugger reports whether comm is on the allowlist.
//
// Exact comparison, not a prefix or substring test. A substring match would
// exempt anything merely containing "gdb" — including a process deliberately
// named "notgdbatall" — which widens an already weak control for no benefit.
func isKnownDebugger(comm string, allowlist []string) bool {
	for _, name := range allowlist {
		if comm == name {
			return true
		}
	}
	return false
}
