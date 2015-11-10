package native

import (
	"syscall"

	"github.com/lunixbochs/usercorn/go/kernel/posix"
)

func Select(nfds int, readFds, writeFds *syscall.FdSet, timespec *posix.Timespec) (int, error) {
	timeout := &syscall.Timeval{Sec: int64(timespec.Sec), Usec: int32(timespec.Nsec / 1000)}
	if err := syscall.Select(nfds, readFds, writeFds, nil, timeout); err != nil {
		return 0, err
	} else {
		max := 0
		read := Fdset32{readFds.Bits}
		write := Fdset32{writeFds.Bits}
		fds := append(read.Fds(), write.Fds()...)
		for _, v := range fds {
			if v > max {
				max = v
			}
		}
		return max + 1, nil
	}
}
