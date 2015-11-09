package linux

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

func (k *LinuxKernel) Uname(buf co.Buf) {
	uname := &models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", k.U.Loader().Arch()}
	// Pad is both OS and arch dependent? :(
	uname.Pad(64)
	posix.Uname(buf, uname)
}
