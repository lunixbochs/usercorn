package x86_64

import (
	cs "github.com/bnagy/gapstone"
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    64,
	Radare:  "x86",
	CS_ARCH: cs.CS_ARCH_X86,
	CS_MODE: cs.CS_MODE_64,
	KS_ARCH: ks.ARCH_X86,
	KS_MODE: ks.MODE_64,
	UC_ARCH: uc.ARCH_X86,
	UC_MODE: uc.MODE_64,
	PC:      uc.X86_REG_RIP,
	SP:      uc.X86_REG_RSP,
	Regs: map[string]int{
		"rax": uc.X86_REG_RAX,
		"rbx": uc.X86_REG_RBX,
		"rcx": uc.X86_REG_RCX,
		"rdx": uc.X86_REG_RDX,
		"rsi": uc.X86_REG_RSI,
		"rdi": uc.X86_REG_RDI,
		"rbp": uc.X86_REG_RBP,
		"rsp": uc.X86_REG_RSP,
		"rip": uc.X86_REG_RIP,
		"r8":  uc.X86_REG_R8,
		"r9":  uc.X86_REG_R9,
		"r10": uc.X86_REG_R10,
		"r11": uc.X86_REG_R11,
		"r12": uc.X86_REG_R12,
		"r13": uc.X86_REG_R13,
		"r14": uc.X86_REG_R14,
		"r15": uc.X86_REG_R15,
		"fs":  uc.X86_REG_FS,
		"gs":  uc.X86_REG_GS,
	},
	DefaultRegs: []string{
		"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"fs", "gs",
	},
	GdbXml: gdbXml,
}

func Wrmsr(u models.Usercorn, msr, value uint64) {
	wrmsr := []byte{0x0F, 0x30}
	u.RunShellcode(
		0, wrmsr,
		map[int]uint64{
			uc.X86_REG_RAX: value & 0xFFFFFFFF,
			uc.X86_REG_RDX: value >> 32 & 0xFFFFFFFF,
			uc.X86_REG_RCX: msr & 0xFFFFFFFF,
		}, nil,
	)
}

func Rdmsr(u models.Usercorn, msr uint64) uint64 {
	rcx, _ := u.RegRead(uc.X86_REG_RCX)
	rdx, _ := u.RegRead(uc.X86_REG_RDX)

	rdmsr := []byte{0x0F, 0x30}
	regs := map[int]uint64{uc.X86_REG_RAX: msr}
	u.RunShellcode(0, rdmsr, regs, nil)
	ecx, _ := u.RegRead(uc.X86_REG_ECX)
	edx, _ := u.RegRead(uc.X86_REG_EDX)

	u.RegWrite(uc.X86_REG_RCX, rcx)
	u.RegWrite(uc.X86_REG_RDX, rdx)
	return (edx << 32) | (ecx & 0xFFFFFFFF)
}
