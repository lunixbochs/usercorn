package linux

import (
	"github.com/lunixbochs/struc"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *LinuxKernel) SetTidAddress(tidptr co.Buf) uint64 {
	return 0
}

var ENOSYS = 38

// timeout is a co.Buf here because some forms of futex don't pass it
func (k *LinuxKernel) Futex(uaddr co.Buf, op, val int, timeout, uaddr2 co.Buf, val3 int) int {
	return -ENOSYS
}

/*
long get_robust_list(int pid, struct robust_list_head **head_ptr,
                     size_t *len_ptr);
long set_robust_list(struct robust_list_head *head, size_t len);
*/

func (k *LinuxKernel) SetRobustList(tid int, head co.Buf)                   {}
func (k *LinuxKernel) GetRobustList(tid int, head co.Buf, size struc.Off_t) {}
