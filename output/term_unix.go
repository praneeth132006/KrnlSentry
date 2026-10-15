//go:build unix

package output

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// terminalSize asks the kernel how large the terminal attached to w is.
//
// The TIOCGWINSZ ioctl is the only answer that stays correct when the window is
// resized mid-run; COLUMNS is exported by the shell at launch and is stale from
// then on, which is why it is only consulted as a fallback.
func terminalSize(w io.Writer) (cols, rows int) {
	f, ok := w.(*os.File)
	if !ok {
		return 0, 0
	}

	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws == nil {
		return 0, 0
	}

	return int(ws.Col), int(ws.Row)
}

// isTerminal reports whether w is a character device, i.e. a terminal rather
// than a pipe or a file.
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
