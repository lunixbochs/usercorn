package x86

import (
	uc "github.com/lunixbochs/unicorn"

	"../../models"
)

var linuxSyscalls = map[int]string{
	1:   "exit",
	2:   "fork",
	3:   "read",
	4:   "write",
	5:   "open",
	6:   "close",
	9:   "link",
	10:  "unlink",
	19:  "lseek",
	90:  "mmap",
	91:  "munmap",
	192: "mmap",
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	var regs = []int{uc.UC_X86_REG_EBX, uc.UC_X86_REG_ECX, uc.UC_X86_REG_EDX, uc.UC_X86_REG_ESI, uc.UC_X86_REG_EDI, uc.UC_X86_REG_EBP}
	args, _ := u.ReadRegs(regs)
	getArgs := func(n int) []uint64 {
		return args[:n]
	}
	eax, _ := u.RegRead(uc.UC_X86_REG_EAX)
	ret, _ := u.Syscall(linuxSyscalls, int(eax), getArgs)
	u.RegWrite(uc.UC_X86_REG_EAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Syscall: LinuxSyscall, Interrupt: LinuxInterrupt})
}
