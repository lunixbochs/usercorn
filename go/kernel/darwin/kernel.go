package darwin

import (
	"crypto/rand"
	"fmt"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/mach"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

const (
	STACK_BASE = 0x60000000
	STACK_SIZE = 0x00800000
)

type DarwinKernel struct {
	*co.KernelBase
	mach.MachKernel
	posix.PosixKernel
}

func NewKernel(u models.Usercorn) *DarwinKernel {
	kernel := &DarwinKernel{
		KernelBase:  &co.KernelBase{},
		MachKernel:  *mach.NewKernel(),
		PosixKernel: *posix.NewKernel(),
	}
	kernel.MachKernel.KernelBase = kernel.KernelBase
	kernel.PosixKernel.KernelBase = kernel.KernelBase
	kernel.U = u
	registerUnpack(kernel)
	return kernel
}

func StackInit(u models.Usercorn, args, env []string) error {
	if err := u.MapStack(STACK_BASE, STACK_SIZE); err != nil {
		return err
	}
	var tmp [8]byte
	rand.Read(tmp[:])
	stackGuard := u.UnpackAddr(tmp[:])

	auxvStrings := []string{
		u.Exe(),
		fmt.Sprintf("stack_guard=0x%x", stackGuard),
	}
	addrs, err := posix.PushStrings(u, auxvStrings...)
	if err != nil {
		return err
	}
	auxv, err := posix.PackAddrs(u, addrs)
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
