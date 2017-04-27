package linux

import (
	"github.com/lunixbochs/struc"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *LinuxKernel) Sysinfo(buf co.Obuf) uint64 {
	var tmp syscall.Sysinfo_t
	err := syscall.Sysinfo(&tmp)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	info := Sysinfo_t{
		Uptime:    struc.Off_t(tmp.Uptime),
		Loads:     [3]struc.Size_t{struc.Size_t(tmp.Loads[0]), struc.Size_t(tmp.Loads[1]), struc.Size_t(tmp.Loads[2])},
		Totalram:  struc.Size_t(tmp.Totalram),
		Freeram:   struc.Size_t(tmp.Freeram),
		Sharedram: struc.Size_t(tmp.Sharedram),
		Bufferram: struc.Size_t(tmp.Bufferram),
		Totalswap: struc.Size_t(tmp.Totalswap),
		Freeswap:  struc.Size_t(tmp.Freeswap),
		Procs:     tmp.Procs,
		Totalhigh: struc.Size_t(tmp.Totalhigh),
		Freehigh:  struc.Size_t(tmp.Freehigh),
		Unit:      tmp.Unit,
	}
	if err := buf.Pack(&info); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}
