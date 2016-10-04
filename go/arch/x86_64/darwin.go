package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/darwin"
	"github.com/lunixbochs/usercorn/go/models"
)

type DarwinKernel struct {
	*darwin.DarwinKernel
}

func (k *DarwinKernel) ThreadFastSetCthreadSelf(addr uint64) uint64 {
	gsmsr := uint64(0xC0000101)
	Wrmsr(k.U, gsmsr, addr)
	
	return 0
}

func (k *DarwinKernel) Syscall(syscallNum int) uint64 {
	//TODO: check if there is such a thing as an "indirect indirect syscall" - in that case we need to fix this to support recursion
	syscallNum |= 0x2000000
	name, _ := num.Darwin_x86_mach[syscallNum]
	ret, _ := k.U.Syscall(syscallNum, name, common.RegArgsShifted(k.U, AbiRegs, 1))
	return ret
}

func DarwinKernels(u models.Usercorn) []interface{} {
	kernel := &DarwinKernel{darwin.NewKernel(u)}
	return []interface{}{kernel}
}

func DarwinInit(u models.Usercorn, args, env []string) error {
	if err := darwin.StackInit(u, args, env); err != nil {
		return err
	}
	
	//commpage
	//TODO: move constants
	var addr_COMM_PAGE_GTOD_GENERATION uint64
	addr_COMM_PAGE_GTOD_GENERATION = 0x00007fffffe00000 + 0x050 + 28
	var addr_COMM_PAGE_NT_GENERATION uint64
	addr_COMM_PAGE_NT_GENERATION = 0x00007fffffe00000 + 0x050 + 24
	
	var commpageAddrBegin uint64
	commpageAddrBegin = 0x00007fffffe00000
	var commpageAddrEnd uint64
	commpageAddrEnd = 0x00007fffffe01fff
	if err := u.MemMap(commpageAddrBegin, commpageAddrEnd - commpageAddrBegin); err != nil {
		return err
	}
	u.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
			u.Printf("\ncommpage Mem write")
		} else {
			u.Printf("\ncommpage Mem read")
			if addr == addr_COMM_PAGE_GTOD_GENERATION {
				//TODO: either write 0 in which case time lookups will fall back to syscalls
				//or write non-zero and write current timestamp to timestamp and timestampNanosecond fields
				one32 := []byte{1, 0, 0, 0}
				u.MemWrite(addr_COMM_PAGE_GTOD_GENERATION, one32)
			}
			if addr == addr_COMM_PAGE_NT_GENERATION {
				//TODO: either write 0 in which case time lookups will fall back to syscalls
				//or write non-zero and write current timestamp to timestamp and timestampNanosecond fields
				one32 := []byte{1, 0, 0, 0}
				u.MemWrite(addr_COMM_PAGE_NT_GENERATION, one32)
			}
		}
		u.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
	}, commpageAddrBegin, commpageAddrEnd)
	
	return AbiInit(u, DarwinSyscall)
}

func DarwinSyscall(u models.Usercorn) {
	//make result "success" (CF unset) by default
	//TODO: actually set CF depending on syscall failure/success
	u.Trampoline(func() error {
		eflags, err := u.RegRead(uc.X86_REG_EFLAGS)
		
		const CF uint64 = 1 << 0
		eflags &= ^CF //unset carry flag
		
		err = u.RegWrite(uc.X86_REG_EFLAGS, eflags)
		return err
	})
	
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Darwin_x86_mach[int(rax)]
	ret, _ := u.Syscall(int(rax), name, common.RegArgs(u, AbiRegs))
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Kernels: DarwinKernels, Init: DarwinInit, Interrupt: DarwinInterrupt})
}
