package x86_64

import (
	uc "github.com/lunixbochs/unicorn"
)

var AbiRegs = []int{uc.UC_X86_REG_RDI, uc.UC_X86_REG_RSI, uc.UC_X86_REG_RDX, uc.UC_X86_REG_R10, uc.UC_X86_REG_R8, uc.UC_X86_REG_R9}
