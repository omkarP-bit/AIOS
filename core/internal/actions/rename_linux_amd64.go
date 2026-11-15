//go:build linux && amd64

package actions

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	atFDCWD             = ^uintptr(99) // -100
	renameNoReplaceFlag = 1
	renameat2Syscall    = 316
)

func renameNoReplace(oldPath, newPath string) error {
	oldPtr, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPtr, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		renameat2Syscall,
		atFDCWD, uintptr(unsafe.Pointer(oldPtr)),
		atFDCWD, uintptr(unsafe.Pointer(newPtr)),
		renameNoReplaceFlag, 0,
	)
	runtime.KeepAlive(oldPtr)
	runtime.KeepAlive(newPtr)
	if errno != 0 {
		return &os.LinkError{Op: "renameat2", Old: oldPath, New: newPath, Err: errno}
	}
	return nil
}
