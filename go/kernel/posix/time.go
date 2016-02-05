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

// TODO: candidate for enum conversion
// but OS X and Linux appeared to have the same values for now
// TODO: these are stubbed because they're mostly for progress bars afaik
func (k *PosixKernel) Setitimer(which int, value co.Obuf) uint64 {
	return 0
}

func (k *PosixKernel) Getitimer(which int, value *native.Itimerval, ovalue co.Obuf) uint64 {
	return 0
}
