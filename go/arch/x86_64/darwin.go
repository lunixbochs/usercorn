package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/darwin"
	"github.com/lunixbochs/usercorn/go/models"
)

type DarwinKernel struct {
	*darwin.DarwinKernel
}

func (k *DarwinKernel) ThreadFastSetCthreadSelf(addr uint64) uint64 {
	gsmsr := uint64(0xC0000101)
	Wrmsr(k.U, gsmsr, addr)
	
	return 0
}

func (k *DarwinKernel) Syscall(syscallNum int) uint64 {
	//TODO: check if there is such a thing as an "indirect indirect syscall" - in that case we need to fix this to support recursion
	syscallNum |= 0x2000000
	name, _ := num.Darwin_x86_mach[syscallNum]
	ret, _ := k.U.Syscall(syscallNum, name, common.RegArgsShifted(k.U, AbiRegs, 1))
	return ret
}

func DarwinKernels(u models.Usercorn) []interface{} {
	kernel := &DarwinKernel{darwin.NewKernel(u)}
	return []interface{}{kernel}
}

func DarwinInit(u models.Usercorn, args, env []string) error {
	if err := darwin.StackInit(u, args, env); err != nil {
		return err
	}
	return AbiInit(u, DarwinSyscall)
}

func DarwinSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Darwin_x86_mach[int(rax)]
	ret, _ := u.Syscall(int(rax), name, common.RegArgs(u, AbiRegs))
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Kernels: DarwinKernels, Init: DarwinInit, Interrupt: DarwinInterrupt})
}
