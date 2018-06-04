package posix

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *PosixKernel) Ioctl(fd co.Fd, req uint64) {}
func (k *PosixKernel) Fcntl(fd co.Fd, cmd int)    {}
func (k *PosixKernel) Fcntl64(fd co.Fd, cmd int)  {}

func (k *PosixKernel) RtSigprocmask() {}
func (k *PosixKernel) RtSigaction()   {}
func (k *PosixKernel) SchedYield()    {}
func (k *PosixKernel) Madvise()       {}
func (k *PosixKernel) Mlock()         {}
func (k *PosixKernel) Munlock()       {}
func (k *PosixKernel) Mlockall()      {}
func (k *PosixKernel) Munlockall()    {}

func (k *PosixKernel) Swapon()  {}
func (k *PosixKernel) Swapoff() {}

func (k *PosixKernel) Gettid() int { return 0 }
