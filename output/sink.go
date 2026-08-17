// Package output writes alerts where people and machines can find them.
//
// Two destinations, deliberately different in shape:
//
//   - JSONL, one alert per line, for machines. Stable field names, no colour,
//     no alignment, append-only. This is the artifact a SIEM ingests.
//   - A formatted line on stdout, for the human watching the terminal.
//
// Both are Sinks, so the agent writes an alert once and does not know or care
// how many places it lands.
package output

import (
	"errors"

	"github.com/praneeth132006/KrnlSentry/detect"
)

// Sink consumes alerts.
//
// Write must be safe for concurrent use: the agent currently calls it from one
// goroutine, but a sink that is only safe by accident of its caller breaks
// silently the first time someone adds a worker.
type Sink interface {
	Write(*detect.Alert) error
	Close() error
}

// MultiSink fans one alert out to several destinations.
//
// Errors from every sink are collected rather than returned on the first
// failure. If the JSONL file has filled the disk, that must not stop the alert
// from reaching the terminal — losing an alert entirely because one of two
// destinations failed is the worst available outcome.
type MultiSink []Sink

// Write sends the alert to every sink.
func (m MultiSink) Write(a *detect.Alert) error {
	var errs []error

	for _, s := range m {
		if s == nil {
			continue
		}
		if err := s.Write(a); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Close closes every sink, again collecting rather than short-circuiting so
// that one stuck destination cannot leak the others' file handles.
func (m MultiSink) Close() error {
	var errs []error

	for _, s := range m {
		if s == nil {
			continue
		}
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
