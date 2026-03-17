//go:build !windows

package app

// initConsole is a no-op on Unix systems where UTF-8 and ANSI colors
// are natively supported.
func initConsole() {}
