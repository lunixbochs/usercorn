package sparc

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "sparc",
	CS_ARCH: cs.CS_ARCH_SPARC,
	CS_MODE: cs.CS_MODE_BIG_ENDIAN,
	UC_ARCH: uc.ARCH_SPARC,
	UC_MODE: uc.MODE_BIG_ENDIAN,
	SP:      uc.SPARC_REG_SP,
	Regs: map[int]string{
		uc.SPARC_REG_G0: "g0",
		uc.SPARC_REG_G1: "g1",
		uc.SPARC_REG_G2: "g2",
		uc.SPARC_REG_G3: "g3",
		uc.SPARC_REG_G4: "g4",
		uc.SPARC_REG_G5: "g5",
		uc.SPARC_REG_G6: "g6",
		uc.SPARC_REG_G7: "g7",
		uc.SPARC_REG_O0: "o0",
		uc.SPARC_REG_O1: "o1",
		uc.SPARC_REG_O2: "o2",
		uc.SPARC_REG_O3: "o3",
		uc.SPARC_REG_O4: "o4",
		uc.SPARC_REG_O5: "o5",
		// uc.SPARC_REG_O6: "o6", // sp
		uc.SPARC_REG_O7: "o7",
		uc.SPARC_REG_L0: "l0",
		uc.SPARC_REG_L1: "l1",
		uc.SPARC_REG_L2: "l2",
		uc.SPARC_REG_L3: "l3",
		uc.SPARC_REG_L4: "l4",
		uc.SPARC_REG_L5: "l5",
		uc.SPARC_REG_L6: "l6",
		uc.SPARC_REG_L7: "l7",
		uc.SPARC_REG_I0: "i0",
		uc.SPARC_REG_I1: "i1",
		uc.SPARC_REG_I2: "i2",
		uc.SPARC_REG_I3: "i3",
		uc.SPARC_REG_I4: "i4",
		uc.SPARC_REG_I5: "i5",
		// uc.SPARC_REG_I6: "i6", // fp
		uc.SPARC_REG_I7: "i7",

		uc.SPARC_REG_SP: "sp",
		uc.SPARC_REG_FP: "fp",
	},
}
