// Package detect turns a stream of observed syscalls into alerts.
//
// This package is the reason the rest of the architecture is shaped the way it
// is. It imports events/ and the standard library — nothing else. There is no
// eBPF here, no ring buffer, no privileged anything. Every rule is an ordinary
// function over an events.Event plus that process's recent history, which means
// the entire detection surface is testable with struct literals on any machine.
//
// Rules live in one file each (privesc.go, sensitivefile.go, ptrace.go,
// revshell.go) and are registered in engine.go.
package detect

import (
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Severity ranks how urgently an alert deserves attention.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

// String returns the uppercase severity name used in logs and JSON output.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "UNKNOWN"
}

// MarshalText makes Severity serialise as "HIGH" rather than as the integer 2.
// Implemented on the value type so both Severity and *Severity satisfy it.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// ParseSeverity is the inverse of String, used by the --min-severity flag.
func ParseSeverity(s string) (Severity, bool) {
	for sev, name := range severityNames {
		if name == s {
			return sev, true
		}
	}
	return SeverityLow, false
}

// Technique is a MITRE ATT&CK technique reference.
//
// Carrying the human-readable name alongside the ID is not decoration. An alert
// tagged only "T1055" forces every reader to go look it up; one that says
// "T1055.008 — Process Injection: Ptrace System Calls" can be triaged on sight
// and grouped by a SIEM without an enrichment step.
type Technique struct {
	ID   string
	Name string
}

// The ATT&CK techniques this tool maps to. Sub-techniques are used wherever one
// applies, since "T1003.008" tells a reviewer far more than the parent
// "T1003" — it names the specific behaviour observed rather than the category.
var (
	TechAbuseElevation = Technique{"T1548", "Abuse Elevation Control Mechanism"}
	TechSetuidSetgid   = Technique{"T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid"}
	TechExploitPrivEsc = Technique{"T1068", "Exploitation for Privilege Escalation"}

	TechCredentialDump = Technique{"T1003", "OS Credential Dumping"}
	TechEtcShadow      = Technique{"T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"}
	TechProcFilesystem = Technique{"T1003.007", "OS Credential Dumping: Proc Filesystem"}
	TechUnsecuredCreds = Technique{"T1552", "Unsecured Credentials"}
	TechCredsInFiles   = Technique{"T1552.001", "Unsecured Credentials: Credentials In Files"}
	TechPrivateKeys    = Technique{"T1552.004", "Unsecured Credentials: Private Keys"}

	TechProcessInjection = Technique{"T1055", "Process Injection"}
	TechPtraceInjection  = Technique{"T1055.008", "Process Injection: Ptrace System Calls"}

	TechCommandInterpreter = Technique{"T1059", "Command and Scripting Interpreter"}
	TechAppLayerProtocol   = Technique{"T1071", "Application Layer Protocol"}
)

// Alert is a single detection.
//
// The JSON field names are the stable output contract — anything parsing
// alerts.jsonl depends on them, so they are chosen to match the spec exactly
// and should be treated as an API.
type Alert struct {
	// Timestamp is wall-clock, RFC3339, because this field is read by
	// humans and correlated against other logs. Rules that need to measure
	// elapsed time use the monotonic Event.Timestamp instead.
	Timestamp time.Time `json:"timestamp"`

	PID  uint32 `json:"pid"`
	TID  uint32 `json:"tid,omitempty"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid,omitempty"`

	Syscall string            `json:"syscall"`
	Args    map[string]string `json:"args"`

	MitreID        string `json:"mitre_id"`
	MitreTechnique string `json:"mitre_technique"`

	Severity Severity `json:"severity"`

	// Description is one line, written to be readable on its own — it has
	// to survive being the only field a pager alert shows.
	Description string `json:"description"`

	// Rule names the rule that fired. Not in the spec's example output, but
	// without it you cannot tell which of several rules produced an alert,
	// which makes tuning and --rules filtering guesswork.
	Rule string `json:"rule"`
}

// newAlert builds an Alert from the event that triggered it, filling in every
// identity field consistently.
//
// Every rule goes through this rather than constructing Alerts directly, so
// that no rule can accidentally omit a field or report the thread id where the
// process id belongs.
func newAlert(ev events.Event, rule string, tech Technique, sev Severity, desc string) *Alert {
	return &Alert{
		Timestamp:      ev.Wall,
		PID:            ev.PID,
		TID:            ev.TID,
		PPID:           ev.PPID,
		Comm:           ev.Comm,
		UID:            ev.UID,
		GID:            ev.GID,
		Syscall:        ev.Syscall,
		Args:           ev.Args,
		MitreID:        tech.ID,
		MitreTechnique: tech.Name,
		Severity:       sev,
		Description:    desc,
		Rule:           rule,
	}
}
