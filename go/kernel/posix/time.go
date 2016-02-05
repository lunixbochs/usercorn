package posix

import (
	"syscall"
	"time"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/native"
)

func (k *PosixKernel) ClockGettime(_ int, out co.Obuf) uint64 {
	ts := syscall.NsecToTimespec(time.Now().UnixNano())
	err := out.Pack(&native.Timespec{int64(ts.Sec), int64(ts.Nsec)})
	if err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}
