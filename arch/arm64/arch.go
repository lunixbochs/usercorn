package arm64

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/lunixbochs/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:      64,
	Radare:    "arm64",
	CS_ARCH:   cs.CS_ARCH_ARM64,
	CS_MODE:   cs.CS_MODE_ARM,
	UC_ARCH:   uc.UC_ARCH_ARM64,
	UC_MODE:   uc.UC_MODE_ARM,
	SP:        uc.UC_ARM64_REG_SP,
	Syscall:   nil,
	Interrupt: interrupt,
}

func interrupt(u models.Usercorn, intno int) {

}
