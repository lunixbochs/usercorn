package x86

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
)

var LinuxRegs = []int{uc.X86_REG_EBX, uc.X86_REG_ECX, uc.X86_REG_EDX, uc.X86_REG_ESI, uc.X86_REG_EDI, uc.X86_REG_EBP}

func LinuxKernels(u models.Usercorn) []interface{} {
	return []interface{}{linux.NewKernel(u)}
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	name, _ := num.Linux_x86[int(eax)]
	ret, _ := u.Syscall(int(eax), name, common.RegArgs(u, LinuxRegs))
	u.RegWrite(uc.X86_REG_EAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "linux",
		Kernels:   LinuxKernels,
		Init:      linux.StackInit,
		Interrupt: LinuxInterrupt,
	})
}
