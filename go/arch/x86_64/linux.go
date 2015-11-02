package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/syscalls"
)

var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "x86_64"}

func LinuxInit(u models.Usercorn, args, env []string) error {
	auxv, err := models.SetupElfAuxv(u)
	if err != nil {
		return err
	}
	return AbiInit(u, args, env, auxv, LinuxSyscall)
}

// TODO: put these somewhere. ghostrace maybe.
const (
	ARCH_SET_GS = 0x1001
	ARCH_SET_FS = 0x1002
	ARCH_GET_FS = 0x1003
	ARCH_GET_GS = 0x1004
)

func linux_arch_prctl(u syscalls.U, args []uint64) uint64 {
	code, _ := u.RegRead(AbiRegs[0])
	addr, _ := u.RegRead(AbiRegs[1])
	var tmp [8]byte
	// TODO: make set check for valid mapped memory
	switch code {
	case ARCH_SET_FS:
		u.RegWrite(uc.X86_REG_FS, addr)
	case ARCH_SET_GS:
		u.RegWrite(uc.X86_REG_GS, addr)
	case ARCH_GET_FS:
		val, _ := u.RegRead(uc.X86_REG_FS)
		buf, _ := u.PackAddr(tmp[:], val)
		u.MemWrite(addr, buf)
	case ARCH_GET_GS:
		val, _ := u.RegRead(uc.X86_REG_GS)
		buf, _ := u.PackAddr(tmp[:], val)
		u.MemWrite(addr, buf)
	}
	return 0
}

func linux_uname(u syscalls.U, args []uint64) uint64 {
	addr, _ := u.RegRead(AbiRegs[0])
	StaticUname.Pad(64)
	syscalls.Uname(u, addr, &StaticUname)
	return 0
}

var overrides = map[string]*syscalls.Syscall{
	"arch_prctl":      {linux_arch_prctl, A{ENUM, PTR}, INT},
	"uname":           {linux_uname, A{PTR}, INT},
	"set_tid_address": {syscalls.Stub, A{PTR}, INT},
}

func LinuxSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Linux_x86_64[int(rax)]
	override, _ := overrides[name]
	ret, _ := u.Syscall(int(rax), name, syscalls.RegArgs(u, AbiRegs), override)
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
