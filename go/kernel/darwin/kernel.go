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
	kernel.MachKernel.U = u
	kernel.PosixKernel.U = u
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
