package x86

import (
	"syscall"

	"github.com/lunixbochs/usercorn/go/kernel/posix"
)

func (f *fdset32) To64() (out [16]int64) {
	for _, fd := range f.Fds() {
		out[fd/16] |= (1 << uint(fd) & (32 - 1))
	}
	return
}

// TODO: 32-bit vs 64-bit
func (f *fdset32) Native() *syscall.FdSet {
	return &syscall.FdSet{f.To64()}
}

func cgcNativeSelect(nfds int, readFds, writeFds *syscall.FdSet, timespec *posix.Timespec) (int, error) {
	// TODO: 32-bit vs 64-bit
	timeout := &syscall.Timeval{Sec: int64(timespec.Sec), Usec: int64(timespec.Nsec / 1000)}
	return syscall.Select(nfds, readFds, writeFds, nil, timeout)
}
