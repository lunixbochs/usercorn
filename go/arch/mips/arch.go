package mips

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "mips",
	CS_ARCH: cs.CS_ARCH_MIPS,
	CS_MODE: cs.CS_MODE_MIPS32 + cs.CS_MODE_LITTLE_ENDIAN,
	UC_ARCH: uc.ARCH_MIPS,
	UC_MODE: uc.MODE_MIPS32 + uc.MODE_LITTLE_ENDIAN,
	PC:      uc.MIPS_REG_PC,
	SP:      uc.MIPS_REG_SP,
	Regs: map[int]string{
		uc.MIPS_REG_AT: "at",
		uc.MIPS_REG_V0: "v0",
		uc.MIPS_REG_V1: "v1",
		uc.MIPS_REG_A0: "a0",
		uc.MIPS_REG_A1: "a1",
		uc.MIPS_REG_A2: "a2",
		uc.MIPS_REG_A3: "a3",
		uc.MIPS_REG_T0: "t0",
		uc.MIPS_REG_T1: "t1",
		uc.MIPS_REG_T2: "t2",
		uc.MIPS_REG_T3: "t3",
		uc.MIPS_REG_T4: "t4",
		uc.MIPS_REG_T5: "t5",
		uc.MIPS_REG_T6: "t6",
		uc.MIPS_REG_T7: "t7",
		uc.MIPS_REG_T8: "t8",
		uc.MIPS_REG_T9: "t9",
		uc.MIPS_REG_S0: "s0",
		uc.MIPS_REG_S1: "s1",
		uc.MIPS_REG_S2: "s2",
		uc.MIPS_REG_S3: "s3",
		uc.MIPS_REG_S4: "s4",
		uc.MIPS_REG_S5: "s5",
		uc.MIPS_REG_S6: "s6",
		uc.MIPS_REG_S7: "s7",
		uc.MIPS_REG_S8: "s8",
		uc.MIPS_REG_K0: "k0",
		uc.MIPS_REG_K1: "k1",
		uc.MIPS_REG_GP: "gp",
		// uc.MIPS_REG_SP: "sp",
		uc.MIPS_REG_RA: "ra",
	},
}
