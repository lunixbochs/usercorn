package redox

import (
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

type RedoxKernel struct {
	posix.PosixKernel
}

func NewKernel() *RedoxKernel {
	kernel := &RedoxKernel{*posix.NewKernel()}
	// FIXME: set up redox packers
	// registerUnpack(kernel)
	// kernel.Pack = Pack
	return kernel
}

func StackInit(u models.Usercorn, args, env []string) error {
	return posix.StackInit(u, args, env, nil)
}
