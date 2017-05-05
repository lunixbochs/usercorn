package x86_16

import (
	"fmt"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	STACK_BASE = 0x8000
	STACK_SIZE = 0x1000
)

var dosSysNum = map[int]string{
	0x00: "terminate",
	//0x01: "input",
	//0x02: "output",
	0x09: "display",
	0x4C: "terminate_with_code",
}

type PSP struct {
	CPMExit                     [2]uint8
	FirstFreeSegment            uint16
	Reserved1                   uint8
	CPMCall5Compat              [5]uint8
	OldTSRAddress               uint32
	OldBreakAddress             uint32
	CriticalErrorHandlerAddress uint32
	CallerPSPSegment            uint16
	JobFileTable                [20]uint8
	EnvironmentSegment          uint16
	INT21SSSP                   uint32
	JobFileTableSize            uint16
	JobFileTablePointer         uint32
	PreviousPSP                 uint32
	Reserved2                   uint32
	DOSVersion                  uint16
	Reserved3                   [14]uint8
	DOSFarCall                  [3]uint8
	Reserved4                   uint16
	ExtendedFCB1                [7]uint8
	FCB1                        [16]uint8
	FCB2                        [20]uint8
	CommandLineLength           uint8
	CommandLine                 [127]byte
}

type DosKernel struct {
	*co.KernelBase
}

func (k *DosKernel) Display(buf co.Buf) {
	// TODO: Read ahead? This'll be slow
	var i uint64
	var mem []uint8
	char := uint8(0)

	for i = 1; char != '$'; i++ {
		mem, _ = k.U.MemRead(buf.Addr, i)
		char = mem[i-1]
	}

	syscall.Write(1, mem[:i-2])
}

func (k *DosKernel) Terminate() {
	k.U.Exit(models.ExitStatus(0)) // TODO: Get correct code
}

func (k *DosKernel) TerminateWithCode(code int) {
	k.U.Exit(models.ExitStatus(code))
}

func NewKernel() *DosKernel {
	return &DosKernel{&co.KernelBase{}}
}

var regNames = []string{
	"ip", "sp", "bp", "ax", "bx", "cx", "dx",
	"si", "di", "flags", "cs", "ds", "es", "ss",
}

func DosInit(u models.Usercorn, args, env []string) error {
	u.RegWrite(u.Arch().SP, STACK_BASE)
	u.SetStackBase(STACK_BASE)
	u.SetStackSize(STACK_SIZE)
	u.SetEntry(0x100)
	return nil
}

func DosSyscall(u models.Usercorn) {
	num, _ := u.RegRead(uc.X86_REG_AH)
	name, _ := dosSysNum[int(num)]
	// TODO: How are registers numbered from here?
	u.Syscall(int(num), name, co.RegArgs(u, X86_16SyscallRegs))
	// TODO: Set error
}

func DosInterrupt(u models.Usercorn, cause uint32) {
	intno := cause & 0xFF
	if intno == 0x21 {
		DosSyscall(u)
		return
	} else if intno == 0x20 {
		// TODO: How to access the terminate METHOD?
		//Terminate()
	} else {
		panic(fmt.Sprintf("unhandled X86 interrupt %d", intno))
	}
}
func DosKernels(u models.Usercorn) []interface{} {
	kernel := &DosKernel{&co.KernelBase{}}
	return []interface{}{kernel}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "DOS",
		Init:      DosInit,
		Interrupt: DosInterrupt,
		Kernels:   DosKernels,
	})
}
