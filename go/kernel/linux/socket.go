package linux

import (
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/native"
)

func fdcount(bufs ...co.Buf) int {
	count := 0
	for _, b := range bufs {
		if b.Addr != 0 {
			var f native.Fdset32
			b.Unpack(&f)
			count += len(f.Fds())
		}
	}
	return count
}

func (k *LinuxKernel) Select(nfds int, readfds, writefds, errorfds co.Buf, timeout *syscall.Timeval) uint64 {
	if errno := k.PosixKernel.Select(nfds, readfds, writefds, errorfds, timeout); errno != 0 {
		return errno
	}
	return uint64(fdcount(readfds, writefds, errorfds))
}
