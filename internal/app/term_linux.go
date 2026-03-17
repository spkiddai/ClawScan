//go:build linux

package app

import "syscall"

const ioctlReadTermios = syscall.TCGETS
