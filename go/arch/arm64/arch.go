package arm64

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    64,
	Radare:  "arm64",
	CS_ARCH: cs.CS_ARCH_ARM64,
	CS_MODE: cs.CS_MODE_ARM,
	UC_ARCH: uc.ARCH_ARM64,
	UC_MODE: uc.MODE_ARM,
	PC:      uc.ARM64_REG_PC,
	SP:      uc.ARM64_REG_SP,
	Regs: map[int]string{
		uc.ARM64_REG_X1:  "x1",
		uc.ARM64_REG_X2:  "x2",
		uc.ARM64_REG_X3:  "x3",
		uc.ARM64_REG_X4:  "x4",
		uc.ARM64_REG_X5:  "x5",
		uc.ARM64_REG_X6:  "x6",
		uc.ARM64_REG_X7:  "x7",
		uc.ARM64_REG_X8:  "x8",
		uc.ARM64_REG_X9:  "x9",
		uc.ARM64_REG_X10: "x10",
		uc.ARM64_REG_X11: "x11",
		uc.ARM64_REG_X12: "x12",
		uc.ARM64_REG_X13: "x13",
		uc.ARM64_REG_X14: "x14",
		uc.ARM64_REG_X15: "x15",
		uc.ARM64_REG_X16: "x16",
		uc.ARM64_REG_X17: "x17",
		uc.ARM64_REG_X18: "x18",
		uc.ARM64_REG_X19: "x19",
		uc.ARM64_REG_X20: "x20",
		uc.ARM64_REG_X21: "x21",
		uc.ARM64_REG_X22: "x22",
		uc.ARM64_REG_X23: "x23",
		uc.ARM64_REG_X24: "x24",
		uc.ARM64_REG_X25: "x25",
		uc.ARM64_REG_X26: "x26",
		uc.ARM64_REG_X27: "x27",
		uc.ARM64_REG_X28: "x28",
		// uc.ARM64_REG_FP:  "fp",
		// uc.ARM64_REG_LR:  "lr",
		// uc.ARM64_REG_SP:  "sp",
		// uc.ARM64_REG_PC:  "pc",
	},
}
