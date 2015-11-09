package darwin

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/mach"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type DarwinKernel struct {
	common.KernelBase
	mach.MachKernel
	posix.PosixKernel

	Unpack common.Unpacker
}

func DefaultKernel() *DarwinKernel {
	return &DarwinKernel{Unpack: Unpack}
}

func NewKernel(u models.Usercorn) common.Kernel {
	kernel := DefaultKernel()
	kernel.UsercornInit(kernel, u)
	return kernel
}
