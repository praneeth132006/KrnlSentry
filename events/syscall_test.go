package events

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestSyscallIDsMatchCHeader is the guard on the one hand-maintained
// correspondence in the project.
//
// Everything else that crosses the kernel/userspace boundary is generated from
// BTF by bpf2go, so it cannot drift. The `enum ks_syscall` values are the
// exception: they are written once in bpf/event.h and again in syscall.go.
// If someone inserts a value in the middle of the C enum and renumbers it,
// every event afterwards is mislabelled — openat events reported as ptrace —
// and nothing else in the build would notice. The failure would show up as
// nonsensical alerts, days later.
//
// So this test parses the actual header and checks it.
func TestSyscallIDsMatchCHeader(t *testing.T) {
	source, err := os.ReadFile("../bpf/event.h")
	if err != nil {
		t.Fatalf("reading bpf/event.h: %v", err)
	}

	// Matches lines like:  KS_SYS_SETRESUID = 6,
	pattern := regexp.MustCompile(`KS_SYS_([A-Z0-9_]+)\s*=\s*(\d+)`)

	matches := pattern.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("no KS_SYS_* entries found in bpf/event.h; has the enum been renamed?")
	}

	if len(matches) != len(syscallNames) {
		t.Errorf("C header declares %d syscalls, Go declares %d — one side is missing an entry",
			len(matches), len(syscallNames))
	}

	for _, m := range matches {
		cName, rawValue := m[1], m[2]

		value, err := strconv.Atoi(rawValue)
		if err != nil {
			t.Fatalf("unparseable value for KS_SYS_%s: %q", cName, rawValue)
		}

		// KS_SYS_SETRESUID -> "setresuid"
		want := strings.ToLower(cName)

		if got := Syscall(value).String(); got != want {
			t.Errorf("KS_SYS_%s = %d: Go maps that ID to %q, C header says %q",
				cName, value, got, want)
		}
	}
}

// TestEventFlagsMatchCHeader does the same for the flag bits.
func TestEventFlagsMatchCHeader(t *testing.T) {
	source, err := os.ReadFile("../bpf/event.h")
	if err != nil {
		t.Fatalf("reading bpf/event.h: %v", err)
	}

	if !strings.Contains(string(source), "#define KS_FLAG_SYS_EXIT (1U << 0)") {
		t.Error("KS_FLAG_SYS_EXIT is no longer defined as bit 0 in bpf/event.h; " +
			"events.FlagSysExit must be updated to match")
	}

	if FlagSysExit != 1 {
		t.Errorf("FlagSysExit = %d, want 1", FlagSysExit)
	}
}

func TestSyscallString(t *testing.T) {
	tests := []struct {
		name string
		id   Syscall
		want string
	}{
		{"known syscall", SysOpenat, "openat"},
		{"zero is unknown", SysUnknown, "unknown"},
		// An unrecognised ID keeps its number rather than collapsing to
		// "unknown", so a kernel/userspace version mismatch is visible
		// in the output instead of silently anonymous.
		{"unrecognised keeps its number", Syscall(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.String(); got != tt.want {
				t.Errorf("Syscall(%d).String() = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestSyscallPredicates(t *testing.T) {
	tests := []struct {
		name      string
		id        Syscall
		exec      bool
		credental bool
		dup       bool
	}{
		{"execve", SysExecve, true, false, false},
		{"execveat", SysExecveat, true, false, false},
		{"openat", SysOpenat, false, false, false},
		{"setuid", SysSetuid, false, true, false},
		{"setresgid", SysSetresgid, false, true, false},
		{"capset is not a uid change", SysCapset, false, false, false},
		{"dup2", SysDup2, false, false, true},
		// dup3 must be treated identically to dup2: arm64 has no dup2
		// syscall at all, so a predicate that omitted dup3 would make
		// the reverse-shell rule silently dead on ARM.
		{"dup3", SysDup3, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.IsExecution(); got != tt.exec {
				t.Errorf("IsExecution() = %v, want %v", got, tt.exec)
			}
			if got := tt.id.IsCredentialChange(); got != tt.credental {
				t.Errorf("IsCredentialChange() = %v, want %v", got, tt.credental)
			}
			if got := tt.id.IsDup(); got != tt.dup {
				t.Errorf("IsDup() = %v, want %v", got, tt.dup)
			}
		})
	}
}
