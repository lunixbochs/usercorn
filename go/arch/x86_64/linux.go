package x86_64

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
	"../../syscalls"
	"../../syscalls/gen"
)

var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "x86_64"}

func LinuxInit(u models.Usercorn, args, env []string) error {
	auxv, err := models.SetupElfAuxv(u)
	if err != nil {
		return err
	}
	if err := u.PushBytes(auxv); err != nil {
		return err
	}
	return AbiInit(u, args, env, auxv, LinuxSyscall)
}

func LinuxSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := gen.Linux_x86_64[int(rax)]
	var ret uint64
	switch name {
	case "uname":
		addr, _ := u.RegRead(AbiRegs[0])
		StaticUname.Pad(64)
		syscalls.Uname(u, addr, &StaticUname)
	case "arch_prctl":
	case "set_tid_address":
	default:
		ret, _ = u.Syscall(int(rax), name, syscalls.RegArgs(u, AbiRegs))
	}
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Init: LinuxInit, Interrupt: LinuxInterrupt})
}
