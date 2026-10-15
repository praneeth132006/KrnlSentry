package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/praneeth132006/KrnlSentry/events"
)

var boot = time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)

type p struct {
	pid, ppid, uid uint32
	comm           string
}

var (
	at  = 3 * time.Hour
	enc = json.NewEncoder(os.Stdout)
)

func emit(pr p, sc events.Syscall, step time.Duration, mut func(*events.Raw)) {
	at += step
	r := events.Raw{
		Timestamp: uint64(at), PID: pr.pid, TGID: pr.pid, UID: pr.uid, GID: pr.uid,
		PPID: pr.ppid, SyscallID: uint32(sc), Comm: pr.comm,
	}
	if mut != nil {
		mut(&r)
	}
	if err := enc.Encode(events.NewRecord(events.Decode(r, boot))); err != nil {
		panic(err)
	}
}

func exec(pr p, step time.Duration, path string, argv ...string) {
	emit(pr, events.SysExecve, step, func(r *events.Raw) { r.Path = path; r.Argv = argv })
}

func open(pr p, step time.Duration, path string) {
	emit(pr, events.SysOpenat, step, func(r *events.Raw) { r.Path = path; r.Arg0 = -100; r.Arg1 = 0o2000000 })
}

func connect(pr p, step time.Duration, daddr uint32, dport uint16) {
	emit(pr, events.SysConnect, step, func(r *events.Raw) {
		r.Arg0 = 3
		r.Family = events.AFInet
		r.Daddr = daddr
		r.Dport = dport
	})
}

func main() {
	sshdSession := p{4090, 812, 0, "sshd"}
	bash := p{4100, 4090, 1000, "bash"}
	ls := p{4105, 4100, 1000, "ls"}
	curl := p{4110, 4100, 1000, "curl"}
	cat := p{4120, 4100, 1000, "cat"}
	inject := p{4130, 4100, 1000, "inject"}
	exploit := p{4140, 4100, 1000, "exploit"}
	py := p{4150, 4100, 1000, "python3"}

	cron := p{700, 1, 0, "cron"}
	backup := p{5200, 700, 0, "backup.sh"}

	// Ordinary login and housekeeping: no alerts expected.
	exec(sshdSession, 0, "/usr/sbin/sshd", "sshd: dev [priv]")
	exec(bash, 40*time.Millisecond, "/bin/bash", "-bash")
	open(bash, 2*time.Millisecond, "/etc/ld.so.cache")
	open(bash, 3*time.Millisecond, "/home/dev/.bashrc")
	exec(ls, 4*time.Second, "/usr/bin/ls", "ls", "-la")
	open(ls, time.Millisecond, "/etc/passwd")

	exec(cron, 100*time.Millisecond, "/usr/sbin/cron", "/usr/sbin/cron", "-f")

	// A nightly backup under cron reads shadow repeatedly: a separate
	// session, one tactic, and a dedup demonstration.
	exec(backup, 300*time.Millisecond, "/usr/local/bin/backup.sh", "backup.sh")
	for i := 0; i < 12; i++ {
		open(backup, 20*time.Millisecond, "/etc/shadow")
	}

	// curl makes a normal outbound connection: socket+connect, no dup2.
	exec(curl, 2*time.Second, "/usr/bin/curl", "curl", "-sO", "https://example.com/x")
	emit(curl, events.SysSocket, time.Millisecond, func(r *events.Raw) { r.Arg0, r.Arg1, r.Arg2 = 2, 1, 6 })
	emit(curl, events.SysSocket, time.Millisecond, func(r *events.Raw) { r.Flags = events.FlagSysExit; r.Ret = 3 })
	connect(curl, time.Millisecond, 0x22d8b85d, 0xbb01) // 93.184.216.34:443

	// The intrusion: credential theft, injection, privilege escalation,
	// then a reverse shell — four siblings under one login shell.
	exec(cat, 9*time.Second, "/usr/bin/cat", "cat", "/home/dev/.aws/credentials")
	open(cat, time.Millisecond, "/home/dev/.aws/credentials")

	exec(inject, 6*time.Second, "/tmp/.x/inject", "inject", "4100")
	emit(inject, events.SysPtrace, 2*time.Millisecond, func(r *events.Raw) { r.Arg0 = 16; r.Arg1 = 4100 })

	exec(exploit, 5*time.Second, "/tmp/.x/exploit", "exploit")
	emit(exploit, events.SysSetuid, 3*time.Millisecond, func(r *events.Raw) { r.Arg0 = 0 })

	exec(py, 7*time.Second, "/usr/bin/python3", "python3", "-c", "import socket,os,pty;s=socket.socket()")
	emit(py, events.SysSocket, 30*time.Millisecond, func(r *events.Raw) { r.Arg0, r.Arg1, r.Arg2 = 2, 1, 6 })
	emit(py, events.SysSocket, time.Millisecond, func(r *events.Raw) { r.Flags = events.FlagSysExit; r.Ret = 3 })
	connect(py, time.Millisecond, 0x09250d0a, 0x5c11) // 10.13.37.9:4444
	for _, fd := range []int64{0, 1, 2} {
		emit(py, events.SysDup2, time.Millisecond, func(r *events.Raw) { r.Arg0 = 3; r.Arg1 = fd })
	}
	exec(py, time.Millisecond, "/bin/sh", "sh", "-i")
}
