package x86_64

import (
	"errors"
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
)

type LinuxKernel struct {
	*linux.LinuxKernel
}

// TODO: put these somewhere. ghostrace maybe.
const (
	ARCH_SET_GS = 0x1001
	ARCH_SET_FS = 0x1002
	ARCH_GET_FS = 0x1003
	ARCH_GET_GS = 0x1004
)

func (k *LinuxKernel) ArchPrctl(code int, addr uint64) {
	fsmsr := uint64(0xC0000100)
	gsmsr := uint64(0xC0000101)

	var tmp [8]byte
	// TODO: make SET check for valid mapped memory
	switch code {
	case ARCH_SET_FS:
		Wrmsr(k.U, fsmsr, addr)
	case ARCH_SET_GS:
		Wrmsr(k.U, gsmsr, addr)
	case ARCH_GET_FS:
		val := Rdmsr(k.U, fsmsr)
		buf, _ := k.U.PackAddr(tmp[:], val)
		k.U.MemWrite(addr, buf)
	case ARCH_GET_GS:
		val := Rdmsr(k.U, gsmsr)
		buf, _ := k.U.PackAddr(tmp[:], val)
		k.U.MemWrite(addr, buf)
	}
}

func (k *LinuxKernel) SetTidAddress() {}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &LinuxKernel{linux.NewKernel()}
	return []interface{}{kernel}
}

func LinuxInit(u models.Usercorn, args, env []string) error {
	if err := linux.StackInit(u, args, env); err != nil {
		return err
	}
	return AbiInit(u, LinuxSyscall)
}

func LinuxSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Linux_x86_64[int(rax)]
	ret, _ := u.Syscall(int(rax), name, common.RegArgs(u, AbiRegs))
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0 {
		u.Exit(errors.New("division by zero"))
	}
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Kernels: LinuxKernels, Init: LinuxInit, Interrupt: LinuxInterrupt})
}
