package linux

import (
	"time"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/native"
)

func (k *LinuxKernel) Gettimeofday(tp co.Obuf, tz *native.Timespec) uint64 {
	now := time.Now()
	res := native.Timespec{
		Sec:  int64(now.Unix()),
		Nsec: int64(now.Nanosecond()),
	}
	if err := tp.Pack(&res); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}
