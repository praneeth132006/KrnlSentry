package detect

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/praneeth132006/KrnlSentry/events"
)

// Rule 5.2 — Sensitive File Access.
//
// Matches openat() paths against a list of files that credential-stealing and
// memory-scraping tooling reads. The matching is done here in user space, not
// in the eBPF program, because glob matching against a table of patterns is
// exactly the kind of work the verifier makes painful and the syscall hot path
// makes expensive.
//
// KNOWN EVASION, STATED PLAINLY
// ─────────────────────────────
// We match the path *as the caller wrote it*. openat("/etc/shadow") is caught;
// a symlink to it, a bind mount, a relative path from a chdir, or an open of
// the underlying block device is not. This is inherent to matching at the
// syscall boundary on an unresolved string, and closing it properly means
// hooking the VFS or an LSM so the resolved inode is available. It is recorded
// in the README rather than glossed over — a detection you cannot state the
// limits of is a detection you cannot rely on.
//
// Note also that only openat() is watched. Modern glibc routes open() through
// openat(), so in practice this covers ordinary programs, but a static binary
// issuing a raw open() syscall would be missed.

var ruleSensitiveFileAccess = Rule{
	Name:        RuleNameSensitiveFile,
	Description: "Access to credential stores, sudo configuration, private keys, or process memory",
	Techniques: []Technique{
		TechCredentialDump,
		TechEtcShadow,
		TechProcFilesystem,
		TechUnsecuredCreds,
		TechCredsInFiles,
		TechPrivateKeys,
	},
	Eval: evalSensitiveFileAccess,
}

// sensitivePath is one entry in the watch list.
//
// match is a function rather than a single glob string because the patterns are
// genuinely different shapes: some are exact paths, some are globs over one
// path segment, and the home-directory ones must match at any depth. Forcing
// them all through path.Match would silently fail for the last group — `*` in
// path.Match does not cross a `/`, so "*/.ssh/id_rsa" never matches
// "/home/alice/.ssh/id_rsa".
type sensitivePath struct {
	label     string
	match     func(p string) bool
	severity  Severity
	technique Technique
	reason    string
}

var sensitivePaths = []sensitivePath{
	{
		label: "/etc/shadow",
		// The trailing-dash variants are the backup files the shadow
		// suite writes, and they contain the same hashes. Reading
		// /etc/shadow- is the same compromise as reading /etc/shadow,
		// and a watch list that omits them has an obvious bypass.
		match: exactAny("/etc/shadow", "/etc/shadow-",
			"/etc/gshadow", "/etc/gshadow-"),
		severity:  SeverityHigh,
		technique: TechEtcShadow,
		reason:    "password hash database",
	},
	{
		label:     "/proc/<pid>/mem",
		match:     globPath("/proc/*/mem"),
		severity:  SeverityHigh,
		technique: TechProcFilesystem,
		reason:    "direct process memory access",
	},
	{
		label:     "/proc/<pid>/maps",
		match:     globPath("/proc/*/maps"),
		severity:  SeverityMedium,
		technique: TechProcFilesystem,
		reason:    "process memory layout enumeration",
	},
	{
		label:     "/etc/sudoers",
		match:     exactAny("/etc/sudoers"),
		severity:  SeverityMedium,
		technique: TechUnsecuredCreds,
		reason:    "sudo policy",
	},
	{
		label:     "/etc/sudoers.d/*",
		match:     prefixMatch("/etc/sudoers.d/"),
		severity:  SeverityMedium,
		technique: TechUnsecuredCreds,
		reason:    "sudo policy fragment",
	},
	{
		label: "~/.ssh private key",
		// Covers every key type OpenSSH generates, not just RSA: an
		// attacker collecting keys does not care which algorithm, and
		// ed25519 is the modern default.
		match: containsAny(
			"/.ssh/id_rsa",
			"/.ssh/id_dsa",
			"/.ssh/id_ecdsa",
			"/.ssh/id_ed25519",
			"/.ssh/identity",
		),
		severity:  SeverityMedium,
		technique: TechPrivateKeys,
		reason:    "SSH private key",
	},
	{
		label:     "~/.aws/credentials",
		match:     containsAny("/.aws/credentials"),
		severity:  SeverityMedium,
		technique: TechCredsInFiles,
		reason:    "cloud provider credentials",
	},
	{
		label:     "~/.gnupg secret keyring",
		match:     containsAny("/.gnupg/secring", "/.gnupg/private-keys-v1.d/"),
		severity:  SeverityMedium,
		technique: TechPrivateKeys,
		reason:    "GnuPG private keyring",
	},
	{
		label:     "~/.docker/config.json",
		match:     containsAny("/.docker/config.json"),
		severity:  SeverityMedium,
		technique: TechCredsInFiles,
		reason:    "container registry credentials",
	},
	{
		label:     "~/.kube/config",
		match:     containsAny("/.kube/config"),
		severity:  SeverityMedium,
		technique: TechCredsInFiles,
		reason:    "Kubernetes cluster credentials",
	},
}

func evalSensitiveFileAccess(c Context) *Alert {
	ev := c.Event

	if ev.IsExit || ev.SyscallID != events.SysOpenat {
		return nil
	}

	if ev.Path == "" {
		return nil
	}

	// Normalise before matching so that "/etc//shadow" and "/etc/./shadow"
	// do not sail past an exact comparison. path.Clean does not resolve
	// symlinks or "..'" beyond the lexical level — it cannot, without
	// touching the filesystem — but it closes the trivial spellings.
	p := path.Clean(ev.Path)

	for _, sp := range sensitivePaths {
		if !sp.match(p) {
			continue
		}

		// A process reading its *own* /proc entry is usually a runtime
		// doing legitimate introspection — allocators, sanitizers and
		// profilers all read /proc/self/maps. It is still reported by
		// default because the spec calls for it and self-inspection is
		// a real unpacking technique, but it is labelled so a triager
		// can see it at a glance, and --ignore-self-proc suppresses it.
		if targetPID, ok := procTargetPID(p); ok {
			self := targetPID == "self" || targetPID == strconv.FormatUint(uint64(ev.PID), 10)
			if self {
				if c.Config.IgnoreSelfProc {
					return nil
				}
				ev.Args["target_self"] = "true"
			}
			ev.Args["target_pid"] = targetPID
		}

		ev.Args["matched_pattern"] = sp.label

		return newAlert(ev, RuleNameSensitiveFile, sp.technique, sp.severity,
			fmt.Sprintf("Process %s opened %q (%s) — possible credential or memory access",
				procLabel(ev), ev.Path, sp.reason))
	}

	return nil
}

// procTargetPID extracts the pid component of a /proc/<pid>/... path.
// The boolean reports whether the path had that shape at all.
func procTargetPID(p string) (string, bool) {
	if !strings.HasPrefix(p, "/proc/") {
		return "", false
	}

	rest := strings.TrimPrefix(p, "/proc/")
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", false
	}

	return rest[:slash], true
}

// ── Matcher constructors ─────────────────────────────────────────────────────
//
// Small closures rather than a switch over a "kind" enum: the table above reads
// as a list of intentions ("exactly these", "anything under here") instead of a
// list of encodings, and adding a new shape does not mean touching the matcher.

// exactAny matches any of the given complete paths.
func exactAny(paths ...string) func(string) bool {
	return func(p string) bool {
		for _, want := range paths {
			if p == want {
				return true
			}
		}
		return false
	}
}

// prefixMatch matches anything beneath a directory.
func prefixMatch(prefix string) func(string) bool {
	return func(p string) bool {
		return strings.HasPrefix(p, prefix) && len(p) > len(prefix)
	}
}

// containsAny matches paths containing any of the given fragments.
//
// Used for home-directory-relative files, where the user's home path is unknown
// and could be anywhere — /home/alice, /root, /Users/bob on a bind mount, or a
// container's /data. The fragments all begin with "/" so they anchor to a path
// segment boundary and cannot match halfway through a directory name.
func containsAny(fragments ...string) func(string) bool {
	return func(p string) bool {
		for _, frag := range fragments {
			if strings.Contains(p, frag) {
				return true
			}
		}
		return false
	}
}

// globPath matches a shell-style glob against the whole path.
//
// path.Match's `*` does not cross `/`, which is exactly what "/proc/*/mem"
// needs: it matches /proc/1234/mem but not /proc/1234/task/5/mem.
//
// A malformed pattern can only come from this file's own literals, so a compile
// error here is a programming mistake rather than a runtime condition; it fails
// closed (no match) rather than panicking in the event path.
func globPath(pattern string) func(string) bool {
	return func(p string) bool {
		ok, err := path.Match(pattern, p)
		return err == nil && ok
	}
}
