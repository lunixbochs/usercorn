package x86_64

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
	"../../syscalls"
)

var linuxSyscalls = map[int]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	20:  "writev",
	21:  "access",
	60:  "exit",
	63:  "uname",
	79:  "getcwd",
	80:  "chdir",
	158: "arch_prctl",
}

var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "x86_64"}

func LinuxSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.UC_X86_REG_RAX)
	name, _ := linuxSyscalls[int(rax)]
	var ret uint64
	switch name {
	case "uname":
		addr, _ := u.RegRead(AbiRegs[0])
		StaticUname.Pad(64)
		syscalls.Uname(u, addr, &StaticUname)
	case "arch_prctl":
	default:
		ret, _ = u.Syscall(int(rax), name, syscalls.RegArgs(u, AbiRegs))
	}
	u.RegWrite(uc.UC_X86_REG_RAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Syscall: LinuxSyscall, Interrupt: LinuxInterrupt})
}
