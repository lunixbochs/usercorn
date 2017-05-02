package mips

import (
	"fmt"
	sysnum "github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
)

var LinuxRegs = []int{uc.MIPS_REG_A0, uc.MIPS_REG_A1, uc.MIPS_REG_A2, uc.MIPS_REG_A3, 0, 0}

type MipsLinuxKernel struct {
	*linux.LinuxKernel
}

func (k *MipsLinuxKernel) SetThreadArea(addr uint64) error {
	// TODO: Unicorn needs CP0 register support
	return k.U.RunAsm(0, "mtc0 $t0, $29", map[int]uint64{uc.MIPS_REG_T0: addr}, nil)
}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &MipsLinuxKernel{LinuxKernel: linux.NewKernel()}
	return []interface{}{kernel}
}

func LinuxInit(u models.Usercorn, args, env []string) error {
	return linux.StackInit(u, args, env)
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	num, _ := u.RegRead(uc.MIPS_REG_V0)
	name, _ := sysnum.Linux_mips[int(num)]
	ret, _ := u.Syscall(int(num), name, common.RegArgs(u, LinuxRegs))
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
	Arch.RegisterOS(&models.OS{
		Name:      "linux",
		Kernels:   LinuxKernels,
		Init:      LinuxInit,
		Interrupt: LinuxInterrupt,
	})
}
