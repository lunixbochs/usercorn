package x86

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "x86",
	CS_ARCH: cs.CS_ARCH_X86,
	CS_MODE: cs.CS_MODE_32,
	UC_ARCH: uc.ARCH_X86,
	UC_MODE: uc.MODE_32,
	PC:      uc.X86_REG_EIP,
	SP:      uc.X86_REG_ESP,
	Regs: map[string]int{
		"eip": uc.X86_REG_EIP,
		"esp": uc.X86_REG_ESP,
		"eax": uc.X86_REG_EAX,
		"ebx": uc.X86_REG_EBX,
		"ecx": uc.X86_REG_ECX,
		"edx": uc.X86_REG_EDX,
		"esi": uc.X86_REG_ESI,
		"edi": uc.X86_REG_EDI,
	},
	DefaultRegs: []string{
		"eax", "ebx", "ecx", "edx", "esi", "edi",
	},
}
