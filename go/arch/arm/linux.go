package arm

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
	90:  "mmap",
	91:  "munmap",
	122: "uname",
	192: "mmap",
}

var LinuxRegs = []int{uc.UC_ARM_REG_R0, uc.UC_ARM_REG_R1, uc.UC_ARM_REG_R2, uc.UC_ARM_REG_R3, uc.UC_ARM_REG_R4, uc.UC_ARM_REG_R5, uc.UC_ARM_REG_R6}
var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "arm"}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	num, _ := u.RegRead(uc.UC_ARM_REG_R7)
	// TODO: EABI has a different syscall base (OABI is 0x900000)
	if num > 0x900000 {
		num -= 0x900000
	}
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
	u.RegWrite(uc.UC_ARM_REG_R0, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	panic(fmt.Sprintf("unhandled ARM interrupt: %d", intno))
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Syscall: LinuxSyscall, Interrupt: LinuxInterrupt})
}
