package arm

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "arm",
	CS_ARCH: cs.CS_ARCH_ARM,
	CS_MODE: cs.CS_MODE_ARM,
	UC_ARCH: uc.UC_ARCH_ARM,
	UC_MODE: uc.UC_MODE_ARM,
	SP:      uc.UC_ARM_REG_SP,
	Regs: map[int]string{
		uc.UC_ARM_REG_R0:   "r0",
		uc.UC_ARM_REG_R1:   "r1",
		uc.UC_ARM_REG_R2:   "r2",
		uc.UC_ARM_REG_R3:   "r3",
		uc.UC_ARM_REG_R4:   "r4",
		uc.UC_ARM_REG_R5:   "r5",
		uc.UC_ARM_REG_R6:   "r6",
		uc.UC_ARM_REG_R7:   "r7",
		uc.UC_ARM_REG_R8:   "r8",
		uc.UC_ARM_REG_R9:   "r9",
		uc.UC_ARM_REG_R10:  "r10",
		uc.UC_ARM_REG_R11:  "r11",
		uc.UC_ARM_REG_R12:  "r12",
		uc.UC_ARM_REG_SP:   "sp",
		uc.UC_ARM_REG_LR:   "lr",
		uc.UC_ARM_REG_PC:   "pc",
		uc.UC_ARM_REG_CPSR: "cpsr",
	},
}
