//go:build !linux

package ebpfloader

import (
	"context"
	"errors"
	"log/slog"

	"github.com/praneeth132006/KrnlSentry/events"
)

// ErrUnsupported is returned by New on any OS other than Linux.
//
// eBPF is a Linux kernel facility, so there is nothing to load here. The stub
// exists so the rest of the agent — and in particular --replay, which needs no
// kernel at all — builds and runs natively on a macOS or Windows laptop
// without clang, bpf2go or a dev container.
var ErrUnsupported = errors.New("live monitoring requires Linux with eBPF; on this OS only --replay is available")

// Collector is a placeholder; New never returns one.
type Collector struct{}

// New always fails on this OS.
func New(*slog.Logger) (*Collector, error) { return nil, ErrUnsupported }

// Run always fails on this OS.
func (*Collector) Run(context.Context, func(events.Event)) error { return ErrUnsupported }

// Stats always fails on this OS.
func (*Collector) Stats() (Stats, error) { return Stats{}, ErrUnsupported }

// Close is a no-op.
func (*Collector) Close() error { return nil }
