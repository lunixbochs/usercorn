package linux

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type LinuxKernel struct {
	posix.PosixKernel
}

func DefaultKernel() *LinuxKernel {
	kernel := &LinuxKernel{}
	kernel.Argjoy.Register(kernel.Unpack)
	return kernel
}

func NewKernel(u models.Usercorn) common.Kernel {
	kernel := DefaultKernel()
	kernel.UsercornInit(kernel, u)
	return kernel
}

func StackInit(u models.Usercorn, args, env []string) error {
	auxv, err := SetupElfAuxv(u)
	if err != nil {
		return err
	}
	return posix.StackInit(u, args, env, auxv)
}
