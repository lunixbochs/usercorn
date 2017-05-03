package linux

import (
	"syscall"
)

func (k *LinuxKernel) Eventfd2(initval, flags uint) uint64 {
	var a3 uintptr
	r1, _, err := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(initval), 
uintptr(flags), a3)
	if err != 0 {
		panic(err)
	}
	return uint64(r1)
}

func (k *LinuxKernel) Eventfd(initval, flags uint) uint64 {
	var a3 uintptr
	r1, _, err := syscall.Syscall(syscall.SYS_EVENTFD, uintptr(initval), 
uintptr(flags), a3)
	if err != 0 {
		panic(err)
	}
	return uint64(r1)

}

