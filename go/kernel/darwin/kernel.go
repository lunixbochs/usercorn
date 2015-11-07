package darwin

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/mach"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type Kernel struct {
	posix.Kernel
	Mach common.Kernel
}

func NewKernel(u models.Usercorn) common.Kernel {
	kernel := &Kernel{
		Mach: mach.NewKernel(u),
	}
	kernel.U = u
	kernel.UsercornInit(kernel)
	return kernel
}

func (k *Kernel) UsercornSyscall(name string) *common.Syscall {
	if sys := k.Mach.UsercornSyscall(name); sys != nil {
		return sys
	}
	if sys := k.Kernel.UsercornSyscall(name); sys != nil {
		return sys
	}
	return nil
}
