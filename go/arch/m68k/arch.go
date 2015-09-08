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
	UC_ARCH: uc.ARCH_M68K,
	UC_MODE: uc.MODE_BIG_ENDIAN,
	SP:      uc.M68K_REG_A7,
	Regs: map[int]string{
		uc.M68K_REG_D0: "d0",
		uc.M68K_REG_D1: "d1",
		uc.M68K_REG_D2: "d2",
		uc.M68K_REG_D3: "d3",
		uc.M68K_REG_D4: "d4",
		uc.M68K_REG_D5: "d5",
		uc.M68K_REG_D6: "d6",
		uc.M68K_REG_D7: "d7",
		uc.M68K_REG_A0: "a0",
		uc.M68K_REG_A1: "a1",
		uc.M68K_REG_A2: "a2",
		uc.M68K_REG_A3: "a3",
		uc.M68K_REG_A4: "a4",
		uc.M68K_REG_A5: "a5",
		uc.M68K_REG_A6: "a6",
		uc.M68K_REG_A7: "sp",
		uc.M68K_REG_PC: "pc",
	},
}
