package detect

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Rule 5.1 — Privilege Escalation.
//
// Four distinct behaviours share one rule because they are one story: a process
// that is not root trying to become root.
//
//   1. setuid(0) / setresuid(0, …) from a non-root process
//   2. setgid(0) / setresgid(0, …) from a non-root process
//   3. capset() from a non-root process
//   4. execve() of a setuid binary by a non-root user
//
// The common gate is "the caller was not already root". That single condition
// removes essentially all of the noise: root processes call setuid() constantly
// and legitimately — every daemon that drops privileges at startup does exactly
// that — and alerting on them would bury the real signal within seconds of
// starting the tool.
//
// This works because the UID on the event is sampled at syscall *entry*, before
// the call takes effect. See fill_common() in krnlsentry.bpf.c: reading it on
// exit would show uid=0 for a successful escalation, and the attack would erase
// its own evidence.

var rulePrivilegeEscalation = Rule{
	Name:        RuleNamePrivilegeEscalation,
	Description: "Non-root process attempting to acquire root identity or capabilities",
	Techniques: []Technique{
		TechAbuseElevation,
		TechSetuidSetgid,
		TechExploitPrivEsc,
	},
	Eval: evalPrivilegeEscalation,
}

// uidUnchanged is the (uid_t)-1 sentinel meaning "leave this id alone".
// It arrives sign-extended from the kernel. Treating it as a target id would
// make every setresuid(-1, -1, -1) look like an escalation attempt.
const uidUnchanged int64 = -1

func evalPrivilegeEscalation(c Context) *Alert {
	ev := c.Event

	// Return probes carry no arguments — nothing to judge.
	if ev.IsExit {
		return nil
	}

	// The gate. Root asking to become root is not an escalation.
	if ev.UID == 0 {
		return nil
	}

	switch ev.SyscallID {
	case events.SysSetuid:
		return evalSetuid(ev)
	case events.SysSetresuid:
		return evalSetresuid(ev)
	case events.SysSetgid:
		return evalSetgid(ev)
	case events.SysSetresgid:
		return evalSetresgid(ev)
	case events.SysCapset:
		return evalCapset(ev)
	case events.SysExecve, events.SysExecveat:
		return evalSuidExec(c)
	}

	return nil
}

func evalSetuid(ev events.Event) *Alert {
	if ev.Arg0 != 0 {
		return nil
	}

	return newAlert(ev, RuleNamePrivilegeEscalation, TechAbuseElevation, SeverityHigh,
		fmt.Sprintf("Process %s called setuid(0) — possible privilege escalation attempt",
			procLabel(ev)))
}

// evalSetresuid covers the call attackers actually use.
//
// setuid() is the textbook example, but exploit payloads overwhelmingly prefer
// setresuid(0,0,0): it sets the real, effective and saved uids in one call and
// leaves no saved uid to be dropped back to. A rule watching only setuid()
// misses most real attempts, which is why this is a separate case rather than
// folded in.
func evalSetresuid(ev events.Event) *Alert {
	targets := []struct {
		name  string
		value int64
	}{
		{"ruid", ev.Arg0},
		{"euid", ev.Arg1},
		{"suid", ev.Arg2},
	}

	var requested []string
	for _, t := range targets {
		if t.value == uidUnchanged {
			continue
		}
		if t.value == 0 {
			requested = append(requested, t.name)
		}
	}

	if len(requested) == 0 {
		return nil
	}

	return newAlert(ev, RuleNamePrivilegeEscalation, TechAbuseElevation, SeverityHigh,
		fmt.Sprintf("Process %s called setresuid() requesting root for %s — possible privilege escalation attempt",
			procLabel(ev), strings.Join(requested, ", ")))
}

func evalSetgid(ev events.Event) *Alert {
	if ev.Arg0 != 0 {
		return nil
	}

	return newAlert(ev, RuleNamePrivilegeEscalation, TechAbuseElevation, SeverityHigh,
		fmt.Sprintf("Process %s called setgid(0) — possible privilege escalation attempt",
			procLabel(ev)))
}

func evalSetresgid(ev events.Event) *Alert {
	targets := []struct {
		name  string
		value int64
	}{
		{"rgid", ev.Arg0},
		{"egid", ev.Arg1},
		{"sgid", ev.Arg2},
	}

	var requested []string
	for _, t := range targets {
		if t.value == uidUnchanged {
			continue
		}
		if t.value == 0 {
			requested = append(requested, t.name)
		}
	}

	if len(requested) == 0 {
		return nil
	}

	return newAlert(ev, RuleNamePrivilegeEscalation, TechAbuseElevation, SeverityHigh,
		fmt.Sprintf("Process %s called setresgid() requesting group root for %s — possible privilege escalation attempt",
			procLabel(ev), strings.Join(requested, ", ")))
}

// evalCapset flags any capset() from a non-root process.
//
// This is knowingly coarse, and the coarseness is the MVP scope from the spec.
// Deciding whether a capset() actually *raises* privileges means diffing the
// requested set against the process's current bounding set — three 64-bit masks
// read from task->cred via CO-RE. Without that diff we cannot distinguish
// raising capabilities from dropping them.
//
// The non-root gate keeps this tolerable: unprivileged processes have very
// little reason to call capset() at all, whereas privileged daemons drop
// capabilities at startup constantly. Full capability diffing is the documented
// stretch goal.
func evalCapset(ev events.Event) *Alert {
	return newAlert(ev, RuleNamePrivilegeEscalation, TechAbuseElevation, SeverityHigh,
		fmt.Sprintf("Process %s called capset() as a non-root user — possible capability manipulation",
			procLabel(ev)))
}

// evalSuidExec flags a non-root user executing a setuid or setgid binary.
//
// The stat happens here in user space, not in the eBPF program, because a
// filesystem metadata lookup is not something a BPF program can or should do.
// That is a deliberate placement, not a workaround: exec is a low-volume
// syscall, so the cost of a stat per event is acceptable in a way it would
// never be for openat.
//
// Two honest caveats:
//
//   - This is a time-of-check/time-of-use race. We stat the path after the
//     execve was observed, so a binary that was replaced in between is reported
//     as whatever it is now. Closing that would require capturing the inode at
//     syscall time in the kernel.
//
//   - Relative paths are skipped. Resolving one needs the process's cwd, and by
//     the time we could read /proc/<pid>/cwd the exec has already replaced the
//     image. Guessing would produce confidently wrong alerts; saying nothing is
//     the lesser failure. Recorded in the README's limitations.
func evalSuidExec(c Context) *Alert {
	ev := c.Event

	path := ev.Path
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil
	}

	info, err := c.Config.Stat(path)
	if err != nil {
		// Overwhelmingly this is ENOENT for a binary that has already
		// been replaced or unlinked, or EACCES on a path we cannot
		// reach. Neither is worth an alert, and neither is an error in
		// this tool.
		return nil
	}

	mode := info.Mode()

	var bits []string
	if mode&os.ModeSetuid != 0 {
		bits = append(bits, "setuid")
	}
	if mode&os.ModeSetgid != 0 {
		bits = append(bits, "setgid")
	}

	if len(bits) == 0 {
		return nil
	}

	// Enrich the alert with the owner, since "setuid binary owned by root"
	// is a materially different finding from "setgid binary owned by tty".
	ev.Args["file_mode"] = formatMode(mode)
	ev.Args["suid_bits"] = strings.Join(bits, ",")

	return newAlert(ev, RuleNamePrivilegeEscalation, TechSetuidSetgid, SeverityHigh,
		fmt.Sprintf("Process %s executed %s binary %q — possible privilege escalation via elevated executable",
			procLabel(ev), strings.Join(bits, "/"), path))
}

// formatMode renders a file mode the way ls -l does, so it can be compared by
// eye against a terminal.
func formatMode(mode fs.FileMode) string {
	return fmt.Sprintf("%s (0%o)", mode.String(), mode.Perm())
}

// procLabel renders the standard "'comm' (PID n, UID n)" identification used in
// every description, so alerts from different rules read consistently.
func procLabel(ev events.Event) string {
	return fmt.Sprintf("%q (PID %d, UID %d)", ev.Comm, ev.PID, ev.UID)
}
