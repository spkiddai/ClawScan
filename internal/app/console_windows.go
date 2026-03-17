//go:build windows

package app

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
)

const (
	cpUTF8                          = 65001
	enableVirtualTerminalProcessing = 0x0004
)

// initConsole sets the Windows console to UTF-8 output and enables ANSI
// escape sequence processing so that colors render correctly.
func initConsole() {
	// Set console output code page to UTF-8
	procSetConsoleOutputCP.Call(uintptr(cpUTF8))

	// Enable virtual terminal processing for ANSI color support
	enableVT(os.Stdout)
	enableVT(os.Stderr)
}

func enableVT(f *os.File) {
	handle := syscall.Handle(f.Fd())
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return
	}
	procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
}
