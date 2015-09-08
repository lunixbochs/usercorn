package x86_64

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

var AbiRegs = []int{uc.X86_REG_RDI, uc.X86_REG_RSI, uc.X86_REG_RDX, uc.X86_REG_R10, uc.X86_REG_R8, uc.X86_REG_R9}
