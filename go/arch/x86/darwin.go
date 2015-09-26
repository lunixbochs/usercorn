package x86

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
	"../../syscalls"
)

func DarwinInit(u models.Usercorn, args, env []string) error {
	return u.PosixInit(args, env, nil)
}

func DarwinSyscall(u models.Usercorn) {
	esp, _ := u.RegRead(uc.X86_REG_ESP)
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	getArgs := syscalls.StackArgs(u)
	name, _ := num.Darwin_x86[int(eax)]
	ret, _ := u.Syscall(int(eax), name, getArgs)
	u.RegWrite(uc.X86_REG_EAX, ret)
	u.RegWrite(uc.X86_REG_ESP, esp)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Init: DarwinInit, Interrupt: DarwinInterrupt})
}
