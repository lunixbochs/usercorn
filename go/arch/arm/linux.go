package arm

import (
	"fmt"
	sysnum "github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
)

var LinuxRegs = []int{uc.ARM_REG_R0, uc.ARM_REG_R1, uc.ARM_REG_R2, uc.ARM_REG_R3, uc.ARM_REG_R4, uc.ARM_REG_R5, uc.ARM_REG_R6}

type ArmLinuxKernel struct {
	*linux.LinuxKernel
}

func (k *ArmLinuxKernel) SetTls(addr uint64) {}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &ArmLinuxKernel{linux.DefaultKernel()}
	kernel.UsercornInit(kernel, u)
	return []interface{}{kernel}
}

func LinuxInit(u models.Usercorn, args, env []string) error {
	return linux.StackInit(u, args, env)
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	num, _ := u.RegRead(uc.ARM_REG_R7)
	// TODO: EABI has a different syscall base (OABI is 0x900000)
	// TODO: does the generator handle this? it needs to.
	if num > 0x900000 {
		num -= 0x900000
	}
	name, _ := sysnum.Linux_arm[int(num)]
	ret, _ := u.Syscall(int(num), name, common.RegArgs(u, LinuxRegs))
	u.RegWrite(uc.ARM_REG_R0, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 2 {
		LinuxSyscall(u)
		return
	}
	panic(fmt.Sprintf("unhandled ARM interrupt: %d", intno))
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "linux",
		Kernels:   LinuxKernels,
		Init:      LinuxInit,
		Interrupt: LinuxInterrupt,
	})
}
