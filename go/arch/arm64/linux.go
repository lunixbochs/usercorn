package arm64

import (
	"fmt"
	sysnum "github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
)

var LinuxRegs = []int{uc.ARM64_REG_X0, uc.ARM64_REG_X1, uc.ARM64_REG_X2, uc.ARM64_REG_X3, uc.ARM64_REG_X4, uc.ARM64_REG_X5}

type ArmLinuxKernel struct {
	*linux.LinuxKernel
	tls uint64
}

func (k *ArmLinuxKernel) SetTls(addr uint64) {
	k.tls = addr
}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &ArmLinuxKernel{LinuxKernel: linux.NewKernel()}
	return []interface{}{kernel}
}

func LinuxInit(u models.Usercorn, args, env []string) error {
	return linux.StackInit(u, args, env)
}

func LinuxSyscall(u models.Usercorn, num int) {
	name, _ := sysnum.Linux_arm[int(num)]
	ret, _ := u.Syscall(int(num), name, common.RegArgs(u, LinuxRegs))
	u.RegWrite(uc.ARM64_REG_X0, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
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
