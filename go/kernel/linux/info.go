package linux

import (
	"github.com/lunixbochs/struc"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

type Sysinfo_t struct {
	Uptime    struc.Off_t
	Loads     [3]struc.Size_t
	Totalram  struc.Size_t
	Freeram   struc.Size_t
	Sharedram struc.Size_t
	Bufferram struc.Size_t
	Totalswap struc.Size_t
	Freeswap  struc.Size_t
	Procs     uint16
	Totalhigh struc.Size_t
	Freehigh  struc.Size_t
	Unit      uint32
}

func (k *LinuxKernel) Uname(buf co.Buf) {
	uname := &models.Uname{
		Sysname:  "Linux",
		Nodename: "usercorn",
		Release:  "3.13.0-24-generic",
		Version:  "normal copy of Linux minding my business",
		Machine:  k.U.Loader().Arch(),
	}
	// Pad is both OS and arch dependent? :(
	uname.Pad(65)
	buf.Pack(uname)
}
