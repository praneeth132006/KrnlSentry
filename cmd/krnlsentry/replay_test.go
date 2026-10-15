package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/praneeth132006/KrnlSentry/detect"
)

// mustWait drives the pacer and fails on anything but a clean wait, so each
// test below reads as a statement about timing rather than about plumbing.
func mustWait(t *testing.T, p *pacer, monotonicNS uint64) {
	t.Helper()

	if err := p.wait(context.Background(), monotonicNS); err != nil {
		t.Fatalf("wait: %v", err)
	}
}

func TestPacerUnpacedDoesNotSleep(t *testing.T) {
	p := newPacer(0)

	start := time.Now()
	mustWait(t, p, 0)
	mustWait(t, p, 10_000_000_000) // ten seconds of capture time

	// Speed 0 is the default and what CI uses: a capture must still replay
	// in milliseconds.
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("unpaced replay slept for %s", elapsed)
	}
}

func TestPacerSleepsForTheGap(t *testing.T) {
	// 200ms of capture time at 10× is 20ms of wall clock.
	p := newPacer(10)

	start := time.Now()
	mustWait(t, p, 1_000_000_000)
	mustWait(t, p, 1_200_000_000)
	elapsed := time.Since(start)

	if elapsed < 10*time.Millisecond {
		t.Errorf("paced replay slept %s, want at least 10ms", elapsed)
	}
	if elapsed > time.Second {
		t.Errorf("paced replay slept %s, far longer than the scaled gap", elapsed)
	}
}

func TestPacerIgnoresBackwardsTime(t *testing.T) {
	// A capture concatenated from two hosts, or hand-edited, can step
	// backwards. Subtracting unsigned timestamps the other way round would
	// sleep for centuries, so the guard is not theoretical.
	p := newPacer(1)

	start := time.Now()
	mustWait(t, p, 10_000_000_000)
	mustWait(t, p, 1_000_000_000)

	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("backwards timestamp slept for %s", elapsed)
	}
}

func TestPacerCapsIdleGaps(t *testing.T) {
	// An hour of idle capture must not look like a hung tool.
	p := newPacer(1)

	start := time.Now()
	mustWait(t, p, 0)
	mustWait(t, p, 3600_000_000_000)

	if elapsed := time.Since(start); elapsed > maxPacedGap+500*time.Millisecond {
		t.Errorf("idle gap slept %s, want it capped near %s", elapsed, maxPacedGap)
	}
}

func TestProgressOf(t *testing.T) {
	cases := []struct {
		read, total int64
		want        float64
	}{
		{0, 100, 0},
		{50, 100, 0.5},
		{100, 100, 1},
		{150, 100, 1}, // a capture that grew while being read
		{10, 0, -1},   // unknown size: no progress bar rather than a stuck one
		{10, -1, -1},
	}

	for _, c := range cases {
		if got := progressOf(c.read, c.total); got != c.want {
			t.Errorf("progressOf(%d, %d) = %v, want %v", c.read, c.total, got, c.want)
		}
	}
}

func TestCountingReaderCountsBytes(t *testing.T) {
	cr := &countingReader{r: strings.NewReader("hello world")}

	buf := make([]byte, 5)
	if _, err := cr.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cr.n != 5 {
		t.Errorf("counted %d bytes, want 5", cr.n)
	}

	if _, err := cr.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cr.n != 10 {
		t.Errorf("counted %d bytes, want 10", cr.n)
	}
}

func TestScopeAndModeLabels(t *testing.T) {
	if got := scopeLabel(0); got != "system-wide" {
		t.Errorf("scopeLabel(0) = %q", got)
	}
	if got := scopeLabel(4821); got != "PID 4821 + descendants" {
		t.Errorf("scopeLabel(4821) = %q", got)
	}
	if got := displayMode(&config{}); got != "live" {
		t.Errorf("displayMode(live) = %q", got)
	}
	if got := displayMode(&config{replayPath: "c.jsonl"}); got != "replay" {
		t.Errorf("displayMode(replay) = %q", got)
	}
}

func TestSplitRules(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"reverse-shell", []string{"reverse-shell"}},
		{" reverse-shell , ptrace ,", []string{"reverse-shell", "ptrace"}},
	}

	for _, c := range cases {
		got := splitRules(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitRules(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitRules(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestMetricsSourceSnapshot(t *testing.T) {
	engine, err := detect.NewEngine(detect.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var c counters
	ms := newMetricsSource(&c, engine, true)

	// Before anything has been read, a replay reports no progress rather
	// than a bar sitting at zero.
	if got := ms.snapshot().Progress; got != -1 {
		t.Errorf("initial progress = %v, want -1", got)
	}

	c.observed.Add(7)
	c.queueDropped.Add(2)
	c.writeErrors.Add(1)
	ms.refresh(0.25)

	snap := ms.snapshot()
	if snap.Observed != 7 || snap.QueueDropped != 2 || snap.WriteErrors != 1 {
		t.Errorf("counters not picked up: %+v", snap)
	}
	if snap.Progress != 0.25 {
		t.Errorf("progress = %v, want 0.25", snap.Progress)
	}

	// A live run has no progress to report at all, whatever is passed.
	live := newMetricsSource(&c, engine, false)
	live.refresh(0.5)
	if got := live.snapshot().Progress; got != -1 {
		t.Errorf("live progress = %v, want -1", got)
	}
}

// The snapshot is written by the pipeline goroutine and read by the painting
// one; under -race this pins that the split is actually locked.
func TestMetricsSourceConcurrentAccess(t *testing.T) {
	engine, err := detect.NewEngine(detect.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var c counters
	ms := newMetricsSource(&c, engine, true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			_ = ms.snapshot()
		}
	}()

	for i := 0; i < 500; i++ {
		c.observed.Add(1)
		ms.refresh(float64(i) / 500)
	}

	<-done
}

func TestPacerStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Both paced and unpaced replays have to answer a Ctrl+C: the paced one
	// may be mid-sleep, and the unpaced one would otherwise read a large
	// capture to the end before noticing.
	for _, speed := range []float64{0, 1} {
		p := newPacer(speed)
		mustWaitStart := p.wait(ctx, 0)

		if !errors.Is(mustWaitStart, errInterrupted) {
			t.Errorf("speed %v: wait returned %v, want errInterrupted", speed, mustWaitStart)
		}
	}
}

func TestPacerCancelledMidSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	p := newPacer(1)
	mustWait(t, p, 0)

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	// A two-second gap, cancelled 20ms in.
	err := p.wait(ctx, 2_000_000_000)

	if !errors.Is(err, errInterrupted) {
		t.Errorf("wait returned %v, want errInterrupted", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancellation took %s to be noticed", elapsed)
	}
}
