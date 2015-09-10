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
	45:  "brk",
	90:  "mmap",
	91:  "munmap",
	122: "uname",
	192: "mmap",
	243: "set_thread_area",
}

var LinuxRegs = []int{uc.X86_REG_EBX, uc.X86_REG_ECX, uc.X86_REG_EDX, uc.X86_REG_ESI, uc.X86_REG_EDI, uc.X86_REG_EBP}
var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "x86"}

func LinuxInit(u models.Usercorn, args, env []string) error {
	return u.PosixInit(args, env)
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	name, _ := linuxSyscalls[int(eax)]
	var ret uint64
	switch name {
	case "uname":
		StaticUname.Pad(64)
		addr, _ := u.RegRead(LinuxRegs[0])
		syscalls.Uname(u, addr, &StaticUname)
	default:
		ret, _ = u.Syscall(int(eax), name, syscalls.RegArgs(u, LinuxRegs))
	}
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
