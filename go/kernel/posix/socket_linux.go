package posix

import (
	"syscall"
)

func (k *PosixKernel) Select(nfds int, readfds, writefds, errorfds *syscall.FdSet, timeout *syscall.Timeval) uint64 {
	if _, err := syscall.Select(nfds, readfds, writefds, errorfds, timeout); err != nil {
		return Errno(err)
	}
	return 0
}
