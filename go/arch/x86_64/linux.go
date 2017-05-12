package x86_64

import (
	"fmt"
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	"github.com/pkg/errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/arch/x86"
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type LinuxKernel struct {
	*linux.LinuxKernel
}

func setupVsyscall(u models.Usercorn, kernel *LinuxKernel) error {
	base := uint64(0xffffffffff600000)
	vgettimeofday := base + 0x0
	vtime := base + 0x400
	vgetcpu := base + 0x800

	// handle x86_64 vsyscall traps
	if err := u.MemMap(base, 0x1000); err != nil {
		return err
	}
	// write 'ret' to trap addrs so they return
	ret := []byte{0xc3}
	if err := u.MemWrite(vgettimeofday, ret); err != nil {
		return err
	}
	if err := u.MemWrite(vtime, ret); err != nil {
		return err
	}
	if err := u.MemWrite(vgetcpu, ret); err != nil {
		return err
	}

	_, err := u.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
		switch addr {
		case vgettimeofday:
			ret, _ := u.Syscall(96, "gettimeofday", common.RegArgs(u, AbiRegs))
			u.RegWrite(uc.X86_REG_RAX, ret)
		case vtime:
			ret, _ := u.Syscall(201, "time", common.RegArgs(u, AbiRegs))
			u.RegWrite(uc.X86_REG_RAX, ret)
		case vgetcpu:
			ret, _ := u.Syscall(309, "getcpu", common.RegArgs(u, AbiRegs))
			u.RegWrite(uc.X86_REG_RAX, ret)
		default:
			panic(fmt.Sprintf("unsupported vsyscall trap: 0x%x\n", addr))
		}
	}, 0xffffffffff600000, 0xffffffffff601000)
	return errors.Wrap(err, "u.HookAdd() failed")
}

// TODO: put these somewhere. ghostrace maybe.
const (
	ARCH_SET_GS = 0x1001
	ARCH_SET_FS = 0x1002
	ARCH_GET_FS = 0x1003
	ARCH_GET_GS = 0x1004
)

func (k *LinuxKernel) ArchPrctl(code int, addr uint64) {
	fsmsr := uint64(0xC0000100)
	gsmsr := uint64(0xC0000101)

	var tmp [8]byte
	// TODO: make SET check for valid mapped memory
	switch code {
	case ARCH_SET_FS:
		x86.Wrmsr(k.U, fsmsr, addr)
	case ARCH_SET_GS:
		x86.Wrmsr(k.U, gsmsr, addr)
	case ARCH_GET_FS:
		val := x86.Rdmsr(k.U, fsmsr)
		buf, _ := k.U.PackAddr(tmp[:], val)
		k.U.MemWrite(addr, buf)
	case ARCH_GET_GS:
		val := x86.Rdmsr(k.U, gsmsr)
		buf, _ := k.U.PackAddr(tmp[:], val)
		k.U.MemWrite(addr, buf)
	}
}

func (k *LinuxKernel) SetTidAddress() {}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &LinuxKernel{linux.NewKernel()}
	// TODO: LinuxInit needs to have a copy of the kernel
	if err := setupVsyscall(u, kernel); err != nil {
		panic(err)
	}
	return []interface{}{kernel}
}

func LinuxInit(u models.Usercorn, args, env []string) error {
	if err := linux.StackInit(u, args, env); err != nil {
		return err
	}
	return AbiInit(u, LinuxSyscall)
}

func LinuxSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Linux_x86_64[int(rax)]
	ret, _ := u.Syscall(int(rax), name, common.RegArgs(u, AbiRegs))
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0 {
		u.Exit(errors.New("division by zero"))
	}
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Kernels: LinuxKernels, Init: LinuxInit, Interrupt: LinuxInterrupt})
}
