package mips

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/lunixbochs/unicorn"

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
}
