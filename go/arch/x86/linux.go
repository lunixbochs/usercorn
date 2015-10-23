package x86

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/syscalls"
)

var LinuxRegs = []int{uc.X86_REG_EBX, uc.X86_REG_ECX, uc.X86_REG_EDX, uc.X86_REG_ESI, uc.X86_REG_EDI, uc.X86_REG_EBP}
var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "x86"}

func LinuxInit(u models.Usercorn, args, env []string) error {
	return u.PosixInit(args, env, nil)
}

func linux_uname(u syscalls.U, args []uint64) uint64 {
	addr, _ := u.RegRead(LinuxRegs[0])
	StaticUname.Pad(64)
	syscalls.Uname(u, addr, &StaticUname)
	return 0
}

var overrides = map[string]*syscalls.Syscall{
	"uname": {linux_uname, A{PTR}, INT},
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	name, _ := num.Linux_x86[int(eax)]
	override, _ := overrides[name]
	ret, _ := u.Syscall(int(eax), name, syscalls.RegArgs(u, LinuxRegs), override)
	u.RegWrite(uc.X86_REG_EAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Init: LinuxInit, Interrupt: LinuxInterrupt})
}
