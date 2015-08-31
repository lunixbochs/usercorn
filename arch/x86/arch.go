package x86

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/lunixbochs/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "x86",
	CS_ARCH: cs.CS_ARCH_X86,
	CS_MODE: cs.CS_MODE_32,
	UC_ARCH: uc.UC_ARCH_X86,
	UC_MODE: uc.UC_MODE_32,
	SP:      uc.UC_X86_REG_ESP,
}
