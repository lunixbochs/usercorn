package posix

import (
	"syscall"
)

func nativeSelect(nfds int, readfds, writefds, errorfds *syscall.FdSet, timeout *syscall.Timeval) error {
	return syscall.Select(nfds, readfds, writefds, errorfds, timeout)
}
