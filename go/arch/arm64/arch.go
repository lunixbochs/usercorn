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
	Regs: map[string]int{
		"x1":  uc.ARM64_REG_X1,
		"x2":  uc.ARM64_REG_X2,
		"x3":  uc.ARM64_REG_X3,
		"x4":  uc.ARM64_REG_X4,
		"x5":  uc.ARM64_REG_X5,
		"x6":  uc.ARM64_REG_X6,
		"x7":  uc.ARM64_REG_X7,
		"x8":  uc.ARM64_REG_X8,
		"x9":  uc.ARM64_REG_X9,
		"x10": uc.ARM64_REG_X10,
		"x11": uc.ARM64_REG_X11,
		"x12": uc.ARM64_REG_X12,
		"x13": uc.ARM64_REG_X13,
		"x14": uc.ARM64_REG_X14,
		"x15": uc.ARM64_REG_X15,
		"x16": uc.ARM64_REG_X16,
		"x17": uc.ARM64_REG_X17,
		"x18": uc.ARM64_REG_X18,
		"x19": uc.ARM64_REG_X19,
		"x20": uc.ARM64_REG_X20,
		"x21": uc.ARM64_REG_X21,
		"x22": uc.ARM64_REG_X22,
		"x23": uc.ARM64_REG_X23,
		"x24": uc.ARM64_REG_X24,
		"x25": uc.ARM64_REG_X25,
		"x26": uc.ARM64_REG_X26,
		"x27": uc.ARM64_REG_X27,
		"x28": uc.ARM64_REG_X28,
		"fp":  uc.ARM64_REG_FP,
		"lr":  uc.ARM64_REG_LR,
		"sp":  uc.ARM64_REG_SP,
		"pc":  uc.ARM64_REG_PC,
	},
	DefaultRegs: []string{
		"x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
		"x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
		"x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
		"x25", "x26", "x27", "x28",
	},
}
