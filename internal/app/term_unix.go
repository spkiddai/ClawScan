//go:build !windows

package app

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal returns true if the given file is connected to a terminal.
func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		ioctlReadTermios,
		uintptr(unsafe.Pointer(&termios)),
		0, 0, 0,
	)
	return err == 0
}
