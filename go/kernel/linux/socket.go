package linux

import (
	"syscall"
)

func countfds(fds *syscall.FdSet) int {
	if fds == nil {
		return 0
	}
	ret := 0
	for _, v := range fds.Bits[:] {
		// don't really care that we're using 64 bits and the underlying type might be 32
		// as left-shifting more than a number's capacity just results in 0 here
		for i := uint64(0); i < 64; i++ {
			if v&(1<<i) == 1 {
				ret += 1
			}
		}
	}
	return ret
}

func (k *LinuxKernel) Select(nfds int, readfds, writefds, errorfds *syscall.FdSet, timeout *syscall.Timeval) uint64 {
	if errno := k.PosixKernel.Select(nfds, readfds, writefds, errorfds, timeout); errno != 0 {
		return errno
	}
	return uint64(countfds(readfds) + countfds(writefds) + countfds(errorfds))
}
