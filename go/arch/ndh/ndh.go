package ndh

import (
	"github.com/lunixbochs/usercorn/go/cpu/ndh"
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
)

var NdhRegs = []int{ndh.R1, ndh.R2, ndh.R3, ndh.R4, ndh.R5, ndh.R6}

var sysNums = map[int]string{
	0x01: "exit",
	0x02: "open",
	0x03: "read",
	0x04: "write",
	0x05: "close",
	0x06: "setuid",
	0x07: "setgid",
	0x08: "dup2",
	0x09: "send",
	0x0a: "recv",
	0x0b: "socket",
	0x0c: "listen",
	0x0d: "bind",
	0x0e: "accept",
	0x0f: "chdir",
	0x10: "chmod",
	0x11: "lseek",
	0x12: "getpid",
	0x13: "getuid",
	0x14: "pause",
}

type NdhKernel struct {
	*linux.LinuxKernel
}

func NdhKernels(u models.Usercorn) []interface{} {
	kernel := &NdhKernel{LinuxKernel: linux.NewKernel()}
	return []interface{}{kernel}
}

func NdhInit(u models.Usercorn, args, env []string) error {
	if err := u.MapStack(0x0, 0x8000, false); err != nil {
		return err
	}
	sp, _ := u.RegRead(ndh.BP)
	u.RegWrite(ndh.BP, sp)
	return nil
}

func NdhSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	num, _ := u.RegRead(ndh.R0)
	name, _ := sysNums[int(num)]
	ret, _ := u.Syscall(int(num), name, common.RegArgs(u, NdhRegs))
	u.RegWrite(ndh.R0, ret)
}

func NdhInterrupt(u models.Usercorn, cause uint32) {
	NdhSyscall(u)
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "ndh",
		Kernels:   NdhKernels,
		Init:      NdhInit,
		Interrupt: NdhInterrupt,
	})
}
