package x86

import (
	"syscall"

	"github.com/lunixbochs/usercorn/go/syscalls"
)

func (f *fdset32) Native() *syscall.FdSet {
	return &syscall.FdSet{f.Bits}
}

func cgcNativeSelect(nfds int, readFds, writeFds *syscall.FdSet, timespec *syscalls.Timespec) (int, error) {
	timeout := &syscall.Timeval{Sec: int64(timespec.Sec), Usec: int32(timespec.Nsec / 1000)}
	if err := syscall.Select(nfds, readFds, writeFds, nil, timeout); err != nil {
		return 0, err
	} else {
		max := 0
		read := fdset32{readFds.Bits}
		write := fdset32{writeFds.Bits}
		fds := append(read.Fds(), write.Fds()...)
		for _, v := range fds {
			if v > max {
				max = v
			}
		}
		return max + 1, nil
	}
}
