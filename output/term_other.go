//go:build !unix

package output

import (
	"io"
	"os"
)

// terminalSize has no portable implementation off unix. Returning zero makes
// the caller fall back to COLUMNS and then to a fixed default, which is the
// right outcome: the dashboard is a convenience, and the agent must build on
// every platform the replay path supports.
func terminalSize(io.Writer) (cols, rows int) { return 0, 0 }

// isTerminal uses the mode bit, which is available everywhere Go runs.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}

	info, err := f.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
