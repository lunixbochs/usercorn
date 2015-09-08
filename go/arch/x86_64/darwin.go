package x86_64

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
	"../../syscalls"
)

var darwinSyscalls = map[int]string{
	1:   "exit",
	2:   "fork",
	3:   "read",
	4:   "write",
	5:   "open",
	6:   "close",
	7:   "wait4",
	9:   "link",
	10:  "unlink",
	73:  "munmap",
	197: "mmap",
	199: "lseek",
}

func DarwinSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	num := int(rax - 0x2000000)
	name, _ := darwinSyscalls[num]
	ret, _ := u.Syscall(num, name, syscalls.RegArgs(u, AbiRegs))
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Init: AbiInit(DarwinSyscall), Interrupt: DarwinInterrupt})
}
