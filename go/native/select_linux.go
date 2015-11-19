package native

import (
	"syscall"
)

func Select(nfds int, readFds, writeFds *syscall.FdSet, timespec *Timespec) (int, error) {
	return syscall.Select(nfds, readFds, writeFds, nil, timespec.Native())
}
