package mach

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

type MachKernel struct {
	common.KernelBase
}

func NewKernel(u models.Usercorn) common.Kernel {
	kernel := &MachKernel{}
	kernel.UsercornInit(kernel, u)
	return kernel
}
