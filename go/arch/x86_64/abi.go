package x86_64

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"../../models"
)

var AbiRegs = []int{uc.X86_REG_RDI, uc.X86_REG_RSI, uc.X86_REG_RDX, uc.X86_REG_R10, uc.X86_REG_R8, uc.X86_REG_R9}

func AbiInit(syscall func(u models.Usercorn)) func(models.Usercorn) {
	return func(u models.Usercorn) {
		u.HookAdd(uc.HOOK_INSN, func(_ uc.Unicorn) {
			syscall(u)
		}, uc.X86_INS_SYSCALL)
	}
}
