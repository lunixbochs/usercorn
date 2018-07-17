package x86_64

import (
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	cs "github.com/lunixbochs/capstr"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/cpu"
	"github.com/lunixbochs/usercorn/go/cpu/unicorn"
	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Name:   "x86_64",
	Bits:   64,
	Radare: "x86",

	Cpu: &unicorn.Builder{Arch: uc.ARCH_X86, Mode: uc.MODE_64},
	Dis: &cpu.Capstr{Arch: cs.ARCH_X86, Mode: cs.MODE_64},
	Asm: &cpu.Keystone{Arch: ks.ARCH_X86, Mode: ks.MODE_64},

	PC: uc.X86_REG_RIP,
	SP: uc.X86_REG_RSP,
	Regs: map[string]int{
		"fs":  uc.X86_REG_FS,
		"gs":  uc.X86_REG_GS,
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
	},
	DefaultRegs: []string{
		"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"rsp", "fs", "gs",
	},
	GdbXml: gdbXml,
}
