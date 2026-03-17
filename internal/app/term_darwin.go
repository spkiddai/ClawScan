//go:build darwin

package app

import "syscall"

const ioctlReadTermios = syscall.TIOCGETA
