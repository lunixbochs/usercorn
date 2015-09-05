package x86

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
	"../../syscalls"
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

var LinuxRegs = []int{uc.UC_X86_REG_EBX, uc.UC_X86_REG_ECX, uc.UC_X86_REG_EDX, uc.UC_X86_REG_ESI, uc.UC_X86_REG_EDI, uc.UC_X86_REG_EBP}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	eax, _ := u.RegRead(uc.UC_X86_REG_EAX)
	name, _ := linuxSyscalls[int(eax)]
	ret, _ := u.Syscall(int(eax), name, syscalls.RegArgs(u, LinuxRegs))
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
