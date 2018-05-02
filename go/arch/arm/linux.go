package arm

import (
	"fmt"
	sysnum "github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

var LinuxRegs = []int{uc.ARM_REG_R0, uc.ARM_REG_R1, uc.ARM_REG_R2, uc.ARM_REG_R3, uc.ARM_REG_R4, uc.ARM_REG_R5, uc.ARM_REG_R6}

type ArmLinuxKernel struct {
	*linux.LinuxKernel
	tls uint64
}

func (k *ArmLinuxKernel) SetTls(addr uint64) {
	k.tls = addr
	k.U.RunAsm(0, "mcr p15, 0, r0, c13, c0, 3",
		map[int]uint64{uc.ARM_REG_R0: addr},
		[]int{uc.ARM_REG_R0},
	)
}

func setupTraps(u models.Usercorn, kernel *ArmLinuxKernel) error {
	// handle arm kernel traps
	// https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt
	if err := u.MemMap(0xffff0000, 0x10000, cpu.PROT_READ|cpu.PROT_EXEC); err != nil {
		return err
	}
	for addr := 0; addr < 0x10000; addr += 4 {
		// write "bx lr" to all kernel trap addresses so they will return
		bxlr := []byte{0x1e, 0xff, 0x2f, 0xe1}
		if err := u.MemWrite(0xffff0000+uint64(addr), bxlr); err != nil {
			return err
		}
	}
	_, err := u.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
		switch addr {
		case 0xffff0fa0:
			// __kuser_memory_barrier
			// *shrug*
		case 0xffff0f60:
			// __kuser_cmpxchg64
			// TODO: DRY possible here?
			oldval, _ := u.RegRead(uc.ARM_REG_R0)
			newval, _ := u.RegRead(uc.ARM_REG_R1)
			ptr, _ := u.RegRead(uc.ARM_REG_R2)
			var tmp [8]byte
			var status uint64 = 1
			if err := u.MemReadInto(tmp[:], ptr); err != nil {
				// error
			} else if u.ByteOrder().Uint64(tmp[:]) == oldval {
				u.ByteOrder().PutUint64(tmp[:], newval)
				u.MemWrite(ptr, tmp[:])
				status = 0
			}
			u.RegWrite(uc.ARM_REG_R0, status)
		case 0xffff0fc0:
			// __kuser_cmpxchg
			// TODO: would this throw a segfault?
			// TODO: flags are not set
			oldval, _ := u.RegRead(uc.ARM_REG_R0)
			newval, _ := u.RegRead(uc.ARM_REG_R1)
			ptr, _ := u.RegRead(uc.ARM_REG_R2)
			var tmp [4]byte
			var status uint64 = 1
			if err := u.MemReadInto(tmp[:], ptr); err != nil {
				// error
			} else if u.UnpackAddr(tmp[:]) == oldval {
				u.PackAddr(tmp[:], newval)
				u.MemWrite(ptr, tmp[:])
				status = 0
			}
			u.RegWrite(uc.ARM_REG_R0, status)
		case 0xffff0fe0:
			// __kuser_get_tls
			u.RegWrite(uc.ARM_REG_R0, kernel.tls)
		case 0xffff0ffc:
			// __kuser_helper_version
			u.RegWrite(uc.ARM_REG_R0, 2)
		default:
			panic(fmt.Sprintf("unsupported kernel trap: 0x%x\n", addr))
		}
	}, 0xffff0000, 0xffffffff)
	return err
}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &ArmLinuxKernel{LinuxKernel: linux.NewKernel()}
	// TODO: LinuxInit needs to have a copy of the kernel
	// honestly init should be part of the kernel?
	if err := setupTraps(u, kernel); err != nil {
		panic(err)
	}
	return []interface{}{kernel}
}

func LinuxInit(u models.Usercorn, args, env []string) error {
	if err := EnableFPU(u); err != nil {
		return err
	}
	/*
		if err := EnterUsermode(u); err != nil {
			return err
		}
	*/
	return linux.StackInit(u, args, env)
}

func LinuxSyscall(u models.Usercorn, num int) {
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
		// TODO: thumb? issue #121
		pc, _ := u.RegRead(uc.ARM_REG_PC)
		var tmp [4]byte
		if err := u.MemReadInto(tmp[:], pc-4); err != nil {
			panic(err)
		}
		n := u.UnpackAddr(tmp[:]) & 0xffff
		if n > 0 {
			LinuxSyscall(u, int(n))
			return
		}

		// TODO: handle errors or something
		num, _ := u.RegRead(uc.ARM_REG_R7)
		LinuxSyscall(u, int(num))
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
