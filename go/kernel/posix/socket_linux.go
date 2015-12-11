package posix

import (
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func nativeSelect(nfds int, readfds, writefds, errorfds co.Buf, timeout *syscall.Timeval) error {
	_, err := syscall.Select(nfds, readfds, writefds, errorfds, timeout)
	return err
}
