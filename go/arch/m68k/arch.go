package m68k

import (
	// cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:   32,
	Radare: "m68k",
	// no capstone support for m68k
	CS_ARCH: 0,
	CS_MODE: 0,
	UC_ARCH: uc.UC_ARCH_M68K,
	UC_MODE: uc.UC_MODE_BIG_ENDIAN,
	SP:      uc.UC_M68K_REG_A7,
	Regs:    map[int]string{},
}
