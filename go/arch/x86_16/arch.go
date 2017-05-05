package x86_16

import (
	cs "github.com/bnagy/gapstone"
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    16,
	Radare:  "x86_16", // TODO: Test
	CS_ARCH: cs.CS_ARCH_X86,
	CS_MODE: cs.CS_MODE_16,
	KS_ARCH: ks.ARCH_X86,
	KS_MODE: ks.MODE_16,
	UC_ARCH: uc.ARCH_X86,
	UC_MODE: uc.MODE_16,
	PC:      uc.X86_REG_IP,
	SP:      uc.X86_REG_SP,
	Regs: map[string]int{
		"ip": uc.X86_REG_IP,
		"sp": uc.X86_REG_SP,
		"bp": uc.X86_REG_BP,
		"ax": uc.X86_REG_AX,
		"bx": uc.X86_REG_BX,
		"cx": uc.X86_REG_CX,
		"dx": uc.X86_REG_DX,
		"si": uc.X86_REG_SI,
		"di": uc.X86_REG_DI,

		"flags": uc.X86_REG_EFLAGS,

		"cs": uc.X86_REG_CS,
		"ds": uc.X86_REG_DS,
		"es": uc.X86_REG_ES,
		"ss": uc.X86_REG_SS,
	},
	DefaultRegs: []string{
		"ax", "bx", "cx", "dx", "si", "di", "bp",
	},
	GdbXml: "", // TODO: Find this GDB xml for x86_16
}
