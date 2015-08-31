package x86_64

import (
	cs "github.com/bnagy/gapstone"
	uc "github.com/lunixbochs/unicorn"

	"../../models"
)

var Arch = &models.Arch{
	Bits:      64,
	Radare:    "x86",
	CS_ARCH:   cs.CS_ARCH_X86,
	CS_MODE:   cs.CS_MODE_64,
	UC_ARCH:   uc.UC_ARCH_X86,
	UC_MODE:   uc.UC_MODE_64,
	SP:        uc.UC_X86_REG_RSP,
	Syscall:   syscall,
	Interrupt: interrupt,
}

func syscall(u models.Usercorn) {

}

func interrupt(u models.Usercorn, intno uint32) {

}
