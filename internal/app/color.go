package app

import (
	"os"
)

// ANSI color escape sequences.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"

	colorBoldRed    = "\033[1;31m"
	colorBoldGreen  = "\033[1;32m"
	colorBoldYellow = "\033[1;33m"
	colorBoldBlue   = "\033[1;34m"
	colorBoldCyan   = "\033[1;36m"
	colorBoldWhite  = "\033[1;37m"
)

// colorEnabled returns true if the terminal supports colored output.
func colorEnabled() bool {
	// Respect NO_COLOR convention: https://no-color.org
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminal(os.Stdout)
}

// colorize wraps text with ANSI color codes. If colors are disabled it
// returns the text unchanged.
func colorize(text, color string, enabled bool) string {
	if !enabled {
		return text
	}
	return color + text + colorReset
}
