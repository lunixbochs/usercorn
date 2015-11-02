package x86

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/syscalls"
)

const (
	dwMach = 1
	dwUnix = 2
	dwMdep = 3
	dwDiag = 4
)

func DarwinInit(u models.Usercorn, args, env []string) error {
	return u.PosixInit(args, env, nil)
}

func DarwinSyscall(u models.Usercorn, class int) {
	// TODO: read args from stack without modifying reg so we don't need to restore esp
	esp, _ := u.RegRead(uc.X86_REG_ESP)
	getArgs := syscalls.StackArgs(u)

	eax, _ := u.RegRead(uc.X86_REG_EAX)
	nr := class<<24 | int(eax)
	name, _ := num.Darwin_x86_mach[nr]

	ret, _ := u.Syscall(nr, name, getArgs, nil)
	u.RegWrite(uc.X86_REG_EAX, ret)
	u.RegWrite(uc.X86_REG_ESP, esp)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	switch intno {
	case 0x80:
		DarwinSyscall(u, dwUnix)
	case 0x81:
		DarwinSyscall(u, dwMach)
	case 0x82:
		DarwinSyscall(u, dwMdep)
	case 0x83:
		DarwinSyscall(u, dwDiag)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Init: DarwinInit, Interrupt: DarwinInterrupt})
}
