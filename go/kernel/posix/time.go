package posix

import (
	"syscall"
	"time"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *Kernel) ClockGettime(_ int, out co.Obuf) uint64 {
	var err error
	ts := syscall.NsecToTimespec(time.Now().UnixNano())
	if k.U.Bits() == 64 {
		err = out.Pack(&Timespec64{ts.Sec, ts.Nsec})
	} else {
		err = out.Pack(&Timespec{int32(ts.Sec), int32(ts.Nsec)})
	}
	if err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}
