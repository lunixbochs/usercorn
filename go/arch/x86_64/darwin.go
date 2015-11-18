package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/darwin"
	"github.com/lunixbochs/usercorn/go/models"
)

type DarwinKernel struct {
	darwin.DarwinKernel
}

func (k *DarwinKernel) ThreadFastSetCthreadSelf(addr uint64) uint64 {
	k.U.RegWrite(uc.X86_REG_GS, addr)
	return 0
}

func DarwinKernels(u models.Usercorn) []interface{} {
	kernel := &DarwinKernel{}
	kernel.UsercornInit(kernel, u)
	return []interface{}{kernel}
}

func DarwinInit(u models.Usercorn, args, env []string) error {
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
	err = AbiInit(u, args, env, auxv, DarwinSyscall)
	if err != nil {
		return err
	}
	// offset to mach_header at exe[0:] in guest memory
	textOffset, _, _ := u.Loader().Header()
	offset := u.Base() + textOffset
	_, err = u.Push(offset)
	return err
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
