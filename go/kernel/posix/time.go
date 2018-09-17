package posix

import (
	"github.com/lunixbochs/struc"
	"syscall"
	"time"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/native"
)

func (k *PosixKernel) Time(out co.Obuf) uint64 {
	t := time.Now().Unix()
	if out.Addr != 0 {
		out.Pack(struc.Size_t(t))
	}
	return uint64(t)
}

func (k *PosixKernel) ClockGettime(_ int, out co.Obuf) uint64 {
	ts := syscall.NsecToTimespec(time.Now().UnixNano())
	err := out.Pack(&native.Timespec{Sec: int64(ts.Sec), Nsec: int64(ts.Nsec)})
	if err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Nanosleep(req *native.Timespec, rem co.Obuf) uint64 {
	time.Sleep(req.Duration())
	// TODO: 1. allow interrupts
	// TODO: 2. handle remaining time
	if err := rem.Pack(&native.Timespec{}); err != nil {
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

func (k *PosixKernel) ClockGetres(clockid int, out co.Obuf) uint64 {
	// TODO: I'm just assuming you have a nanosecond-accurate clock available
	if out.Addr != 0 {
		res := native.Timespec{
			Sec:  0,
			Nsec: 1,
		}
		if err := out.Pack(&res); err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return 0
}
