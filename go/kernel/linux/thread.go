package linux

import (
	"fmt"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

const (
	FUTEX_WAIT            = 0
	FUTEX_WAKE            = 1
	FUTEX_FD              = 2
	FUTEX_REQUEUE         = 3
	FUTEX_CMP_REQUEUE     = 4
	FUTEX_WAKE_OP         = 5
	FUTEX_LOCK_PI         = 6
	FUTEX_UNLOCK_PI       = 7
	FUTEX_TRYLOCK_PI      = 8
	FUTEX_WAIT_BITSET     = 9
	FUTEX_WAKE_BITSET     = 10
	FUTEX_WAIT_REQUEUE_PI = 11
	FUTEX_CMP_REQUEUE_PI  = 12
)

const (
	FUTEX_PRIVATE_FLAG   = 128
	FUTEX_CLOCK_REALTIME = 256
	FUTEX_CMD_MASK       = ^(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)
)

var ENOSYS = 33

// timeout is a co.Buf here because some forms of futex don't pass it
func (k *LinuxKernel) Futex(uaddr co.Buf, op, val int, timeout, uaddr2 co.Buf, val3 uint64) int {
	if op&FUTEX_CLOCK_REALTIME != 0 {
		return -ENOSYS
	}
	switch op & FUTEX_CMD_MASK {
	case FUTEX_WAIT:
	case FUTEX_WAKE:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAKE_BITSET:
	default:
		return -1
	}
	return 0
}

func (k *LinuxKernel) SetTidAddress(tidptr co.Buf) uint64 {
	return 0
}

func (k *LinuxKernel) Tgkill(tgid int, tid int, sig int) uint64 {
	return 0
}

/*
long get_robust_list(int pid, struct robust_list_head **head_ptr,
                     size_t *len_ptr);
long set_robust_list(struct robust_list_head *head, size_t len);
*/

func (k *LinuxKernel) SetRobustList(tid int, head co.Buf)              {}
func (k *LinuxKernel) GetRobustList(tid int, head co.Buf, size co.Off) {}

func (k *LinuxKernel) Clone(flags uint64, stack, ptid, ctid, regs co.Buf) {
	var uregs [18]uint32
	regs.Unpack(&uregs)
	for i, v := range uregs {
		fmt.Printf("reg[%d] %#x\n", i, v)
	}
	panic("clone unimplemented")
}
