package redox

import (
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

const (
	STACK_BASE = 0x60000000
	STACK_SIZE = 0x00800000
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
	if err := u.MapStack(STACK_BASE, STACK_SIZE); err != nil {
		return err
	}
	return posix.StackInit(u, args, env, nil)
}
