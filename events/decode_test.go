package events

import (
	"testing"
	"time"
)

// bootRef is a fixed boot instant so decoded wall times are deterministic.
var bootRef = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

func TestDecodeIdentityFields(t *testing.T) {
	raw := Raw{
		Timestamp: uint64(90 * time.Second),
		PID:       4825, // thread id
		TGID:      4821, // process id
		UID:       1000,
		GID:       1000,
		PPID:      4802,
		SyscallID: uint32(SysSetuid),
		Comm:      "bash",
	}

	ev := Decode(raw, bootRef)

	// The kernel's "pid" is a thread id and its "tgid" is what users call a
	// PID. Getting this backwards would make every alert name the wrong
	// process, so it is asserted explicitly rather than assumed.
	if ev.PID != 4821 {
		t.Errorf("PID = %d, want 4821 (the tgid)", ev.PID)
	}
	if ev.TID != 4825 {
		t.Errorf("TID = %d, want 4825 (the kernel pid)", ev.TID)
	}

	wantWall := bootRef.Add(90 * time.Second)
	if !ev.Wall.Equal(wantWall) {
		t.Errorf("Wall = %v, want %v", ev.Wall, wantWall)
	}

	if ev.Timestamp != raw.Timestamp {
		t.Errorf("monotonic Timestamp was altered: got %d, want %d", ev.Timestamp, raw.Timestamp)
	}

	if ev.Syscall != "setuid" {
		t.Errorf("Syscall = %q, want \"setuid\"", ev.Syscall)
	}
}

func TestDecodeArgs(t *testing.T) {
	tests := []struct {
		name     string
		raw      Raw
		wantArgs map[string]string
	}{
		{
			name: "openat decodes flags symbolically",
			raw: Raw{
				SyscallID: uint32(SysOpenat),
				Path:      "/etc/shadow",
				Arg0:      -100,      // AT_FDCWD
				Arg1:      0o2000000, // O_RDONLY|O_CLOEXEC
			},
			wantArgs: map[string]string{
				"path":  "/etc/shadow",
				"dfd":   "AT_FDCWD",
				"flags": "O_RDONLY|O_CLOEXEC",
			},
		},
		{
			// mode is only meaningful with O_CREAT; otherwise the
			// kernel ignores the register and it holds garbage, so
			// reporting it would be inventing data.
			name: "openat omits mode without O_CREAT",
			raw: Raw{
				SyscallID: uint32(SysOpenat),
				Path:      "/tmp/x",
				Arg1:      0,
				Arg2:      0o777,
			},
			wantArgs: map[string]string{
				"path":  "/tmp/x",
				"dfd":   "0",
				"flags": "O_RDONLY",
			},
		},
		{
			name: "openat includes mode with O_CREAT",
			raw: Raw{
				SyscallID: uint32(SysOpenat),
				Path:      "/tmp/x",
				Arg1:      0o101, // O_WRONLY|O_CREAT
				Arg2:      0o644,
			},
			wantArgs: map[string]string{
				"path":  "/tmp/x",
				"dfd":   "0",
				"flags": "O_WRONLY|O_CREAT",
				"mode":  "0644",
			},
		},
		{
			// (uid_t)-1 means "leave unchanged". Rendering it as a
			// number would make setresuid(-1,-1,0) look like three
			// escalation requests instead of one.
			name: "setresuid renders the unchanged sentinel",
			raw: Raw{
				SyscallID: uint32(SysSetresuid),
				Arg0:      -1,
				Arg1:      0,
				Arg2:      -1,
			},
			wantArgs: map[string]string{
				"ruid": "unchanged",
				"euid": "0",
				"suid": "unchanged",
			},
		},
		{
			name: "ptrace names the request",
			raw: Raw{
				SyscallID: uint32(SysPtrace),
				Arg0:      PtraceAttach,
				Arg1:      1234,
			},
			wantArgs: map[string]string{
				"request":    "PTRACE_ATTACH",
				"target_pid": "1234",
			},
		},
		{
			// addr is only meaningful for the peek/poke family;
			// for ATTACH it must be zero and showing it invites
			// misreading.
			name: "ptrace includes addr only for memory ops",
			raw: Raw{
				SyscallID: uint32(SysPtrace),
				Arg0:      PtracePoketext,
				Arg1:      1234,
				Arg2:      0x7fff0000,
			},
			wantArgs: map[string]string{
				"request":    "PTRACE_POKETEXT",
				"target_pid": "1234",
				"addr":       "0x7fff0000",
			},
		},
		{
			name: "dup2 names the standard streams",
			raw: Raw{
				SyscallID: uint32(SysDup2),
				Arg0:      7,
				Arg1:      1,
			},
			wantArgs: map[string]string{
				"oldfd": "7",
				"newfd": "1 (stdout)",
			},
		},
		{
			name: "socket masks flags off the type",
			raw: Raw{
				SyscallID: uint32(SysSocket),
				Arg0:      2,          // AF_INET
				Arg1:      1 | 0o4000, // SOCK_STREAM|SOCK_NONBLOCK
				Arg2:      6,
			},
			wantArgs: map[string]string{
				"family":   "AF_INET",
				"type":     "SOCK_STREAM|SOCK_NONBLOCK",
				"protocol": "6",
			},
		},
		{
			name: "execveat names AT_EMPTY_PATH",
			raw: Raw{
				SyscallID: uint32(SysExecveat),
				Path:      "",
				Arg0:      3,
				Arg1:      0x1000, // AT_EMPTY_PATH
			},
			wantArgs: map[string]string{
				"path":  "",
				"dfd":   "3",
				"flags": "AT_EMPTY_PATH",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := Decode(tt.raw, bootRef)

			for k, want := range tt.wantArgs {
				got, ok := ev.Args[k]
				if !ok {
					t.Errorf("missing arg %q (got %v)", k, ev.Args)
					continue
				}
				if got != want {
					t.Errorf("arg %q = %q, want %q", k, got, want)
				}
			}

			for k := range ev.Args {
				if _, expected := tt.wantArgs[k]; !expected {
					t.Errorf("unexpected arg %q = %q", k, ev.Args[k])
				}
			}
		})
	}
}

func TestDecodeConnectAddress(t *testing.T) {
	// 127.0.0.1:4444 in network byte order, as it would sit in a
	// sockaddr_in read out of the traced process.
	raw := Raw{
		SyscallID: uint32(SysConnect),
		Family:    AFInet,
		Daddr:     0x0100007f, // 127.0.0.1 little-endian-stored big-endian bytes
		Dport:     0x5c11,     // 4444 byte-swapped
		Arg0:      3,
	}

	ev := Decode(raw, bootRef)

	if ev.DestIP != "127.0.0.1" {
		t.Errorf("DestIP = %q, want \"127.0.0.1\"", ev.DestIP)
	}
	if ev.DestPort != 4444 {
		t.Errorf("DestPort = %d, want 4444", ev.DestPort)
	}
	if got := ev.Args["dest"]; got != "127.0.0.1:4444" {
		t.Errorf("args[dest] = %q, want \"127.0.0.1:4444\"", got)
	}
	if !ev.IsLoopback() {
		t.Error("IsLoopback() = false for 127.0.0.1")
	}
}

// TestDecodeExitEventSkipsArgs pins down a correctness property that is easy to
// get wrong: on a sys_exit probe the argument registers have already been
// clobbered, so decoding them would produce confident nonsense.
func TestDecodeExitEventSkipsArgs(t *testing.T) {
	raw := Raw{
		SyscallID: uint32(SysSocket),
		Flags:     FlagSysExit,
		Ret:       7,
		Arg0:      0xdeadbeef, // register garbage by this point
	}

	ev := Decode(raw, bootRef)

	if !ev.IsExit {
		t.Fatal("IsExit = false for an event with FlagSysExit set")
	}
	if ev.Args["ret"] != "7" {
		t.Errorf("args[ret] = %q, want \"7\"", ev.Args["ret"])
	}
	if _, present := ev.Args["family"]; present {
		t.Error("exit event decoded entry arguments; register contents are meaningless here")
	}
}

func TestDecodeExitErrnoNaming(t *testing.T) {
	raw := Raw{
		SyscallID: uint32(SysConnect),
		Flags:     FlagSysExit,
		Ret:       -111, // ECONNREFUSED
	}

	ev := Decode(raw, bootRef)

	if got := ev.Args["error"]; got != "ECONNREFUSED" {
		t.Errorf("args[error] = %q, want \"ECONNREFUSED\"", got)
	}
}

func TestFormatOpenFlags(t *testing.T) {
	tests := []struct {
		flags int64
		want  string
	}{
		{0, "O_RDONLY"},
		{1, "O_WRONLY"},
		// The access mode is a value in the low two bits, not a bitmask.
		// Treating it as flags would render O_RDWR as "O_WRONLY|O_RDONLY".
		{2, "O_RDWR"},
		{0o100 | 1, "O_WRONLY|O_CREAT"},
		{0o2000000, "O_RDONLY|O_CLOEXEC"},
		// O_TMPFILE contains O_DIRECTORY; without the compound check it
		// would be reported as a directory open.
		{0o20200000, "O_RDONLY|O_TMPFILE"},
		// Unknown bits are surfaced as hex rather than silently dropped.
		{1 << 30, "O_RDONLY|0x40000000"},
	}

	for _, tt := range tests {
		if got := formatOpenFlags(tt.flags); got != tt.want {
			t.Errorf("formatOpenFlags(0o%o) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestNtohs(t *testing.T) {
	if got := ntohs(0x5c11); got != 4444 {
		t.Errorf("ntohs(0x5c11) = %d, want 4444", got)
	}
}
