package arm

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "arm",
	CS_ARCH: cs.CS_ARCH_ARM,
	CS_MODE: cs.CS_MODE_ARM,
	UC_ARCH: uc.ARCH_ARM,
	UC_MODE: uc.MODE_ARM,
	PC:      uc.ARM_REG_PC,
	SP:      uc.ARM_REG_SP,
	Regs: map[string]int{
		"r0":  uc.ARM_REG_R0,
		"r1":  uc.ARM_REG_R1,
		"r2":  uc.ARM_REG_R2,
		"r3":  uc.ARM_REG_R3,
		"r4":  uc.ARM_REG_R4,
		"r5":  uc.ARM_REG_R5,
		"r6":  uc.ARM_REG_R6,
		"r7":  uc.ARM_REG_R7,
		"r8":  uc.ARM_REG_R8,
		"r9":  uc.ARM_REG_R9,
		"r10": uc.ARM_REG_R10,
		"r11": uc.ARM_REG_R11,
		"r12": uc.ARM_REG_R12,
		"lr":  uc.ARM_REG_LR,
		"sp":  uc.ARM_REG_SP,
		"pc":  uc.ARM_REG_PC,
	},
	DefaultRegs: []string{
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
		"r9", "r10", "r11", "r12",
	},
}
