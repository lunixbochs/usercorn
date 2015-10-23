package mips

import (
	"fmt"
	sysnum "github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/syscalls"
)

var LinuxRegs = []int{uc.MIPS_REG_A0, uc.MIPS_REG_A1, uc.MIPS_REG_A2, uc.MIPS_REG_A3}
var StaticUname = models.Uname{"Linux", "usercorn", "3.13.0-24-generic", "normal copy of Linux minding my business", "mips"}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	num, _ := u.RegRead(uc.MIPS_REG_V0)
	name, _ := sysnum.Linux_mips[int(num)]
	var ret uint64
	switch name {
	case "uname":
		StaticUname.Pad(64)
		addr, _ := u.RegRead(LinuxRegs[0])
		syscalls.Uname(u, addr, &StaticUname)
	default:
		ret, _ = u.Syscall(int(num), name, syscalls.RegArgs(u, LinuxRegs), nil)
	}
	u.RegWrite(uc.MIPS_REG_V0, ret)
}

func LinuxInterrupt(u models.Usercorn, cause uint32) {
	intno := (cause >> 1) & 15
	if intno == 8 {
		LinuxSyscall(u)
		return
	}
	panic(fmt.Sprintf("unhandled MIPS interrupt %d", intno))
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Interrupt: LinuxInterrupt})
}
