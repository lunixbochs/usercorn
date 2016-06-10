package x86

import (
	cs "github.com/bnagy/gapstone"
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "x86",
	CS_ARCH: cs.CS_ARCH_X86,
	CS_MODE: cs.CS_MODE_32,
	KS_ARCH: ks.ARCH_X86,
	KS_MODE: ks.MODE_32,
	UC_ARCH: uc.ARCH_X86,
	UC_MODE: uc.MODE_32,
	PC:      uc.X86_REG_EIP,
	SP:      uc.X86_REG_ESP,
	Regs: map[string]int{
		"eip": uc.X86_REG_EIP,
		"esp": uc.X86_REG_ESP,
		"ebp": uc.X86_REG_EBP,
		"eax": uc.X86_REG_EAX,
		"ebx": uc.X86_REG_EBX,
		"ecx": uc.X86_REG_ECX,
		"edx": uc.X86_REG_EDX,
		"esi": uc.X86_REG_ESI,
		"edi": uc.X86_REG_EDI,

		"eflags": uc.X86_REG_EFLAGS,

		"cs": uc.X86_REG_CS,
		"ds": uc.X86_REG_DS,
		"es": uc.X86_REG_ES,
		"fs": uc.X86_REG_FS,
		"gs": uc.X86_REG_GS,
		"ss": uc.X86_REG_SS,

		/* // TODO: can't handle 80-bit regs
		"st0": uc.X86_REG_ST0,
		"st1": uc.X86_REG_ST0,
		"st2": uc.X86_REG_ST0,
		"st3": uc.X86_REG_ST0,
		"st4": uc.X86_REG_ST0,
		"st5": uc.X86_REG_ST0,
		"st6": uc.X86_REG_ST0,
		"st7": uc.X86_REG_ST0,
		*/

	},
	DefaultRegs: []string{
		"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
	},
	GdbXml: gdbXml,
}
