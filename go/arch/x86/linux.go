package x86

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

var LinuxRegs = []int{uc.X86_REG_EBX, uc.X86_REG_ECX, uc.X86_REG_EDX, uc.X86_REG_ESI, uc.X86_REG_EDI, uc.X86_REG_EBP}

type LinuxKernel struct {
	*linux.LinuxKernel
}

var socketCallMap = map[int]string{
	1:  "socket",
	2:  "bind",
	3:  "connect",
	4:  "listen",
	5:  "accept",
	6:  "getsockname",
	7:  "getpeername",
	8:  "socketpair",
	9:  "send",
	10: "recv",
	11: "sendto",
	12: "recvfrom",
	13: "shutdown",
	14: "setsockopt",
	15: "getsockopt",
	16: "sendmsg",
	17: "recvmsg",
	18: "accept4",
}

func (k *LinuxKernel) Socketcall(index int, params co.Buf) uint64 {
	if name, ok := socketCallMap[index]; ok {
		if sys := k.UsercornSyscall(name); sys != nil {
			rawArgs := make([]uint32, len(sys.In))
			if err := params.Unpack(rawArgs); err != nil {
				return posix.UINT64_MAX
			}
			args := make([]uint64, len(rawArgs))
			for i, v := range rawArgs {
				args[i] = uint64(v)
			}
			return sys.Call(args)
		}
	}
	return posix.UINT64_MAX // FIXME
}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &LinuxKernel{linux.DefaultKernel()}
	kernel.UsercornInit(kernel, u)
	return []interface{}{kernel}
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	name, _ := num.Linux_x86[int(eax)]
	ret, _ := u.Syscall(int(eax), name, co.RegArgs(u, LinuxRegs))
	u.RegWrite(uc.X86_REG_EAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "linux",
		Kernels:   LinuxKernels,
		Init:      linux.StackInit,
		Interrupt: LinuxInterrupt,
	})
}
