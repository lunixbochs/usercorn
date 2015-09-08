package x86_64

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:    64,
	Radare:  "x86",
	CS_ARCH: cs.CS_ARCH_X86,
	CS_MODE: cs.CS_MODE_64,
	UC_ARCH: uc.ARCH_X86,
	UC_MODE: uc.MODE_64,
	SP:      uc.X86_REG_RSP,
	Regs: map[int]string{
		uc.X86_REG_RAX: "rax",
		uc.X86_REG_RBX: "rbx",
		uc.X86_REG_RCX: "rcx",
		uc.X86_REG_RDX: "rdx",
		uc.X86_REG_RSI: "rsi",
		uc.X86_REG_RDI: "rdi",
		uc.X86_REG_RBP: "rbp",
		uc.X86_REG_RSP: "rsp",
		uc.X86_REG_R8:  "r8",
		uc.X86_REG_R9:  "r9",
		uc.X86_REG_R10: "r10",
		uc.X86_REG_R11: "r11",
		uc.X86_REG_R12: "r12",
		uc.X86_REG_R13: "r13",
		uc.X86_REG_R14: "r14",
		uc.X86_REG_R15: "r15",
	},
}
