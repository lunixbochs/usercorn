package linux

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

type Kernel struct {
	common.KernelBase
}

func NewKernel(u models.Usercorn) common.Kernel {
	kernel := &Kernel{common.KernelBase{U: u}}
	kernel.UsercornInit(kernel)
	return kernel
}
