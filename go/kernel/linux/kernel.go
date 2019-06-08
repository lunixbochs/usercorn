package linux

import (
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

const (
	STACK_BASE = 0xbf800000
	STACK_SIZE = 0x00800000
)


type sigaltstack_t struct {
	Stackpointer uint64
	Size         int64
	Flags        int64
}

type LinuxKernel struct {
	posix.PosixKernel
	CurrentStack sigaltstack_t
	IsDumpable uint64
}

func NewKernel() *LinuxKernel {
	kernel := &LinuxKernel{
		*posix.NewKernel(),
		sigaltstack_t{},
		1,
	}
	registerUnpack(kernel)
	kernel.Pack = Pack
	return kernel
}

func StackInit(u models.Usercorn, args, env []string) error {
	if err := u.MapStack(STACK_BASE, STACK_SIZE, false); err != nil {
		return err
	}
	auxv, err := SetupElfAuxv(u)
	if err != nil {
		return err
	}
	return posix.StackInit(u, args, env, auxv)
}
