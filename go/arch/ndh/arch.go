package ndh

import (
	"github.com/lunixbochs/usercorn/go/models"

	"github.com/lunixbochs/usercorn/go/cpu/ndh"
)

var Arch = &models.Arch{
	Name: "ndh",
	Bits: 16,

	Cpu: &ndh.Builder{},
	Dis: &ndh.Dis{},
	Asm: nil,

	PC: ndh.PC,
	SP: ndh.SP,
	Regs: map[string]int{
		"r0": ndh.R0,
		"r1": ndh.R1,
		"r2": ndh.R2,
		"r3": ndh.R3,
		"r4": ndh.R4,
		"r5": ndh.R5,
		"r6": ndh.R6,
		"r7": ndh.R7,
		"bp": ndh.BP,
		"sp": ndh.SP,
		"pc": ndh.PC,
	},
	DefaultRegs: []string{
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "bp",
	},
}
