package mips

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "mips",
	CS_ARCH: cs.CS_ARCH_MIPS,
	CS_MODE: cs.CS_MODE_MIPS32 + cs.CS_MODE_LITTLE_ENDIAN,
	UC_ARCH: uc.UC_ARCH_MIPS,
	UC_MODE: uc.UC_MODE_MIPS32 + uc.UC_MODE_LITTLE_ENDIAN,
	SP:      uc.UC_MIPS_REG_SP,
	Regs: map[int]string{
		uc.UC_MIPS_REG_AT: "at",
		uc.UC_MIPS_REG_V0: "v0",
		uc.UC_MIPS_REG_V1: "v1",
		uc.UC_MIPS_REG_A0: "a0",
		uc.UC_MIPS_REG_A1: "a1",
		uc.UC_MIPS_REG_A2: "a2",
		uc.UC_MIPS_REG_A3: "a3",
		uc.UC_MIPS_REG_T0: "t0",
		uc.UC_MIPS_REG_T1: "t1",
		uc.UC_MIPS_REG_T2: "t2",
		uc.UC_MIPS_REG_T3: "t3",
		uc.UC_MIPS_REG_T4: "t4",
		uc.UC_MIPS_REG_T5: "t5",
		uc.UC_MIPS_REG_T6: "t6",
		uc.UC_MIPS_REG_T7: "t7",
		uc.UC_MIPS_REG_T8: "t8",
		uc.UC_MIPS_REG_T9: "t9",
		uc.UC_MIPS_REG_S0: "s0",
		uc.UC_MIPS_REG_S1: "s1",
		uc.UC_MIPS_REG_S2: "s2",
		uc.UC_MIPS_REG_S3: "s3",
		uc.UC_MIPS_REG_S4: "s4",
		uc.UC_MIPS_REG_S5: "s5",
		uc.UC_MIPS_REG_S6: "s6",
		uc.UC_MIPS_REG_S7: "s7",
		uc.UC_MIPS_REG_S8: "s8",
		uc.UC_MIPS_REG_K0: "k0",
		uc.UC_MIPS_REG_K1: "k1",
		uc.UC_MIPS_REG_GP: "gp",
		uc.UC_MIPS_REG_SP: "sp",
		uc.UC_MIPS_REG_RA: "ra",
	},
}
