package linux

import (
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type LinuxKernel struct {
	posix.PosixKernel
}

func NewKernel() *LinuxKernel {
	kernel := &LinuxKernel{*posix.NewKernel()}
	registerUnpack(kernel)
	kernel.Pack = Pack
	return kernel
}

func StackInit(u models.Usercorn, args, env []string) error {
	auxv, err := SetupElfAuxv(u)
	if err != nil {
		return err
	}
	return posix.StackInit(u, args, env, auxv)
}
