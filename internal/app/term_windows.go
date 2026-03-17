//go:build windows

package app

import (
	"os"
	"syscall"
)

// isTerminal returns true if the given file is connected to a Windows console.
func isTerminal(f *os.File) bool {
	handle := syscall.Handle(f.Fd())
	var mode uint32
	err := syscall.GetConsoleMode(handle, &mode)
	return err == nil
}
