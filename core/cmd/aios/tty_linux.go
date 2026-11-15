//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// stdinIsTerminal asks the kernel for terminal attributes. ModeCharDevice is
// not enough: /dev/null is also a character device.
func stdinIsTerminal() bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, os.Stdin.Fd(),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return errno == 0
}
