package events

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestRecordRoundTrip is what makes --replay trustworthy: every field a rule
// computes on must survive being written by --verbose and read back.
func TestRecordRoundTrip(t *testing.T) {
	boot := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)

	raws := []Raw{
		{Timestamp: 1_500_000_000, PID: 11, TGID: 10, UID: 1000, GID: 1000, PPID: 9,
			SyscallID: uint32(SysExecve), Comm: "bash", Path: "/bin/sh", Argv: []string{"sh", "-i"}},
		{Timestamp: 1_600_000_000, PID: 10, TGID: 10, UID: 1000, PPID: 9,
			SyscallID: uint32(SysConnect), Arg0: 3, Family: AFInet, Daddr: 0x0100007f, Dport: 0x5c11, Comm: "nc"},
		{Timestamp: 1_700_000_000, PID: 10, TGID: 10, UID: 1000, PPID: 9,
			SyscallID: uint32(SysSocket), Flags: FlagSysExit, Ret: 3, Comm: "nc"},
		{Timestamp: 1_800_000_000, PID: 10, TGID: 10, UID: 1000, PPID: 9,
			SyscallID: uint32(SysDup2), Arg0: 3, Arg1: 1, Comm: "nc"},
	}

	for _, raw := range raws {
		want := Decode(raw, boot)

		data, err := json.Marshal(NewRecord(want))
		if err != nil {
			t.Fatal(err)
		}

		var got Event
		if err := ReadRecords(bytes.NewReader(data), func(ev Event) error { got = ev; return nil }); err != nil {
			t.Fatalf("%s: %v", want.Syscall, err)
		}

		// Wall is written at millisecond precision; everything else must
		// be exact.
		if !got.Wall.Equal(want.Wall.Truncate(time.Millisecond)) {
			t.Errorf("%s: wall %v, want %v", want.Syscall, got.Wall, want.Wall)
		}
		got.Wall, want.Wall = time.Time{}, time.Time{}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s round trip mismatch:\n got  %+v\n want %+v", want.Syscall, got, want)
		}
	}
}

func TestReadRecordsErrors(t *testing.T) {
	good := `{"timestamp":"2026-10-05T08:00:00.000Z","pid":1,"syscall":"openat","path":"/x"}`

	cases := []struct {
		name, input, wantErr string
		wantEvents           int
	}{
		{"blank lines skipped", "\n" + good + "\n\n" + good + "\n", "", 2},
		{"truncated final line tolerated", good + "\n" + `{"timestamp":"2026-10`, "", 1},
		{"corrupt middle line is an error", good + "\n{oops\n" + good + "\n", "line 2", 1},
		{"unknown syscall is an error", strings.Replace(good, "openat", "unknown(17)", 1), "unknown syscall", 0},
		{"bad timestamp is an error", strings.Replace(good, "2026-10-05T08:00:00.000Z", "yesterday", 1), "bad timestamp", 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := 0
			err := ReadRecords(strings.NewReader(c.input), func(Event) error { n++; return nil })

			if c.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
			}
			if n != c.wantEvents {
				t.Errorf("delivered %d events, want %d", n, c.wantEvents)
			}
		})
	}
}

func TestParseSyscallCoversEveryName(t *testing.T) {
	for sc, name := range syscallNames {
		if sc == SysUnknown {
			continue
		}
		got, ok := ParseSyscall(name)
		if !ok || got != sc {
			t.Errorf("ParseSyscall(%q) = %v, %v; want %v", name, got, ok, sc)
		}
	}
	if _, ok := ParseSyscall("unknown"); ok {
		t.Error("ParseSyscall accepted \"unknown\"")
	}
}
