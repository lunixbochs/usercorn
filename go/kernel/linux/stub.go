package linux

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

// timeout is a co.Buf here because some forms of futex don't pass it
func (k *LinuxKernel) Futex(uaddr co.Buf, op, val int, timeout, uaddr2 co.Buf, val3 int) {
}

func (k *LinuxKernel) Fadvise64() {}
func (k *LinuxKernel) Utimensat() {}
func (k *LinuxKernel) Prlimit()   {}
func (k *LinuxKernel) Prlimit64() {}

func (k *LinuxKernel) SetRobustList() {}
func (k *LinuxKernel) GetRobustList() {}
