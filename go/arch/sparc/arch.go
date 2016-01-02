package sparc

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "sparc",
	CS_ARCH: cs.CS_ARCH_SPARC,
	CS_MODE: cs.CS_MODE_32,
	UC_ARCH: uc.ARCH_SPARC,
	UC_MODE: uc.MODE_32,
	PC:      uc.SPARC_REG_PC,
	SP:      uc.SPARC_REG_SP,
	Regs: map[string]int{
		// "g0": uc.SPARC_REG_G0, // g0 is always zero
		"g1": uc.SPARC_REG_G1,
		"g2": uc.SPARC_REG_G2,
		"g3": uc.SPARC_REG_G3,
		"g4": uc.SPARC_REG_G4,
		"g5": uc.SPARC_REG_G5,
		"g6": uc.SPARC_REG_G6,
		"g7": uc.SPARC_REG_G7,
		"o0": uc.SPARC_REG_O0,
		"o1": uc.SPARC_REG_O1,
		"o2": uc.SPARC_REG_O2,
		"o3": uc.SPARC_REG_O3,
		"o4": uc.SPARC_REG_O4,
		"o5": uc.SPARC_REG_O5,
		"o6": uc.SPARC_REG_O6, // sp
		"o7": uc.SPARC_REG_O7,
		"l0": uc.SPARC_REG_L0,
		"l1": uc.SPARC_REG_L1,
		"l2": uc.SPARC_REG_L2,
		"l3": uc.SPARC_REG_L3,
		"l4": uc.SPARC_REG_L4,
		"l5": uc.SPARC_REG_L5,
		"l6": uc.SPARC_REG_L6,
		"l7": uc.SPARC_REG_L7,
		"i0": uc.SPARC_REG_I0,
		"i1": uc.SPARC_REG_I1,
		"i2": uc.SPARC_REG_I2,
		"i3": uc.SPARC_REG_I3,
		"i4": uc.SPARC_REG_I4,
		"i5": uc.SPARC_REG_I5,
		"i6": uc.SPARC_REG_I6, // fp
		"i7": uc.SPARC_REG_I7,

		"sp": uc.SPARC_REG_SP,
		"fp": uc.SPARC_REG_FP,
	},
	DefaultRegs: []string{
		"g1", "g2", "g3", "g4", "g5", "g6", "g7",
		"o0", "o1", "o2", "o3", "o4", "o5", "o7",
		"l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
		"i0", "i1", "i2", "i3", "i4", "i5", "i7",
	},
}
