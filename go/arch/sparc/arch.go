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
	UC_ARCH: uc.UC_ARCH_SPARC,
	UC_MODE: uc.UC_MODE_BIG_ENDIAN,
	SP:      uc.UC_SPARC_REG_SP,
	Regs:    map[int]string{},
}
