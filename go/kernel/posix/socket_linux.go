package posix

import (
	"syscall"
)

func nativeSelect(nfds int, readfds, writefds, errorfds *syscall.FdSet, timeout *syscall.Timeval) error {
	_, err := syscall.Select(nfds, readfds, writefds, errorfds, timeout)
	return err
}
