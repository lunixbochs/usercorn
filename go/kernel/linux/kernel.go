package linux

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type Kernel struct {
	posix.Kernel
}

func NewKernel(u models.Usercorn) common.Kernel {
	kernel := &Kernel{}
	kernel.U = u
	kernel.UsercornInit(kernel)
	return kernel
}
