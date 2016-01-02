package darwin

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/mach"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type DarwinKernel struct {
	co.KernelBase
	mach.MachKernel
	posix.PosixKernel
}

func DefaultKernel() *DarwinKernel {
	kernel := &DarwinKernel{}
	kernel.Argjoy.Register(Unpack)
	return kernel
}

func (k *DarwinKernel) UsercornInit(i co.Kernel, u models.Usercorn) {
	k.MachKernel.U = u
	k.PosixKernel.U = u
	k.KernelBase.UsercornInit(i, u)
}

func NewKernel(u models.Usercorn) co.Kernel {
	kernel := DefaultKernel()
	kernel.UsercornInit(kernel, u)
	return kernel
}

func StackInit(u models.Usercorn, args, env []string) error {
	exe := u.Exe()
	addr, err := u.PushBytes([]byte(exe + "\x00"))
	if err != nil {
		return err
	}
	var tmp [8]byte
	auxv, err := u.PackAddr(tmp[:], addr)
	if err != nil {
		return err
	}
	err = posix.StackInit(u, args, env, auxv)
	if err != nil {
		return err
	}
	// offset to mach_header at exe[0:] in guest memory
	textOffset, _, _ := u.Loader().Header()
	offset := u.Base() + textOffset
	_, err = u.Push(offset)
	return err
}
