package native

import (
	"syscall"
)

func Select(nfds int, readFds, writeFds *syscall.FdSet, timespec *Timespec) (int, error) {
	// TODO: 32-bit vs 64-bit
	timeout := &syscall.Timeval{Sec: int64(timespec.Sec), Usec: int64(timespec.Nsec / 1000)}
	return syscall.Select(nfds, readFds, writeFds, nil, timeout)
}
