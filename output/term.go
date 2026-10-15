package output

import (
	"io"
	"os"
	"strconv"
)

// Fallbacks for a terminal whose size cannot be determined: 100×30 is a
// conservative modern default, and every panel is built to degrade rather than
// wrap if the real terminal turns out to be smaller.
const (
	fallbackCols = 100
	fallbackRows = 30
)

// terminalWidth returns the usable column count for w.
func terminalWidth(w io.Writer) int {
	if cols, _ := terminalSize(w); cols > 0 {
		return cols
	}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	return fallbackCols
}

// terminalHeight returns the usable row count for w.
func terminalHeight(w io.Writer) int {
	if _, rows := terminalSize(w); rows > 0 {
		return rows
	}
	if n, err := strconv.Atoi(os.Getenv("LINES")); err == nil && n > 0 {
		return n
	}
	return fallbackRows
}
