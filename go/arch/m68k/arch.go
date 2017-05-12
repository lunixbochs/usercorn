package m68k

import (
	// cs "github.com/bnagy/gapstone"
	// ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	// "github.com/lunixbochs/usercorn/go/cpu"
	"github.com/lunixbochs/usercorn/go/cpu/unicorn"
	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Name:   "m68k",
	Bits:   32,
	Radare: "m68k",

	Cpu: &unicorn.Builder{Arch: uc.ARCH_M68K, Mode: uc.MODE_BIG_ENDIAN},
	// no capstone support for m68k
	Asm: nil,
	Dis: nil,

	PC: uc.M68K_REG_PC,
	SP: uc.M68K_REG_A7,
	Regs: map[string]int{
		"d0": uc.M68K_REG_D0,
		"d1": uc.M68K_REG_D1,
		"d2": uc.M68K_REG_D2,
		"d3": uc.M68K_REG_D3,
		"d4": uc.M68K_REG_D4,
		"d5": uc.M68K_REG_D5,
		"d6": uc.M68K_REG_D6,
		"d7": uc.M68K_REG_D7,
		"a0": uc.M68K_REG_A0,
		"a1": uc.M68K_REG_A1,
		"a2": uc.M68K_REG_A2,
		"a3": uc.M68K_REG_A3,
		"a4": uc.M68K_REG_A4,
		"a5": uc.M68K_REG_A5,
		"a6": uc.M68K_REG_A6,
		"sp": uc.M68K_REG_A7,
		"pc": uc.M68K_REG_PC,
	},
	DefaultRegs: []string{
		"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
		"a0", "a1", "a2", "a3", "a4", "a5", "a6",
	},
}
