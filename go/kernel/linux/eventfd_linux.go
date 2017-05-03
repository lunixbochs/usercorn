package linux

import (
	"syscall"
)

func (k *LinuxKernel) Eventfd2(initval, flags uint) (uint64, error) {
	var a3 uintptr
	r1, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(initval), uintptr(flags), a3)
	if errno != 0 {
		return 0, errno
	}
	return uint64(r1), nil

}

func (k *LinuxKernel) Eventfd(initval, flags uint) (uint64, error) {
	var a3 uintptr
	r1, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(initval), uintptr(flags), a3)
	if errno != 0 {
		return 0, errno
	}
	return uint64(r1), nil

}
