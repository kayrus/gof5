// +build linux,!cgo
// +build go1.16

package psx // import "kernel.org/pub/linux/libs/security/libcap/psx"

import (
	"syscall"
)

// Syscall3 and Syscall6 are aliases for syscall.AllThreadsSyscall*
// when compiled CGO_ENABLED=0.
var (
	Syscall3 = syscall.AllThreadsSyscall
	Syscall6 = syscall.AllThreadsSyscall6
)
