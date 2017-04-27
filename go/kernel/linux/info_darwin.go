package linux

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *LinuxKernel) Sysinfo(buf co.Obuf) uint64 {
	info := Sysinfo_t{
	// FIXME (need sysctl)
	}
	if err := buf.Pack(&info); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}
