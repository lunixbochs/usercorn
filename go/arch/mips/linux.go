package mips

import (
	"fmt"
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
	61:  "uname",
	90:  "mmap",
	91:  "munmap",
	210: "mmap",
}

var LinuxRegs = []int{uc.UC_MIPS_REG_A0, uc.UC_MIPS_REG_A1, uc.UC_MIPS_REG_A2, uc.UC_MIPS_REG_A3}
var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "mips"}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	num, _ := u.RegRead(uc.UC_MIPS_REG_V0)
	// 32-bit mips linux syscalls range from 4000 to 4999
	num -= 4000
	name, _ := linuxSyscalls[int(num)]
	var ret uint64
	switch name {
	case "uname":
		StaticUname.Pad(64)
		addr, _ := u.RegRead(LinuxRegs[0])
		syscalls.Uname(u, addr, &StaticUname)
	default:
		ret, _ = u.Syscall(int(num), name, syscalls.RegArgs(u, LinuxRegs))
	}
	u.RegWrite(uc.UC_MIPS_REG_V0, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	panic(fmt.Sprintf("unhandled MIPS interrupt %d", intno))
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Syscall: LinuxSyscall, Interrupt: LinuxInterrupt})
}
