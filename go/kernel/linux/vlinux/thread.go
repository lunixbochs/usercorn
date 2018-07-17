package vlinux

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
)

// SetTidAddress syscall (not implemented)
func (k *VirtualLinuxKernel) SetTidAddress(tidptr co.Buf) uint64 {
	return 0
}

// SetRobustList syscall (not implemented)
func (k *VirtualLinuxKernel) SetRobustList(tid int, head co.Buf) {}

// Futex syscall
// Timeout is a co.Buf here because some forms of futex don't pass it
func (k *VirtualLinuxKernel) Futex(uaddr co.Buf, op, val int, timeout, uaddr2 co.Buf, val3 uint64) int {
	if op&linux.FUTEX_CLOCK_REALTIME != 0 {
		return -linux.ENOSYS
	}
	switch op & linux.FUTEX_CMD_MASK {
	case linux.FUTEX_WAIT:
	case linux.FUTEX_WAKE:
	case linux.FUTEX_WAIT_BITSET:
	case linux.FUTEX_WAKE_BITSET:
	default:
		return -1
	}
	return 0
}
