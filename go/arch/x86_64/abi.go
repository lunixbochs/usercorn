package x86_64

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var AbiRegs = []int{uc.X86_REG_RDI, uc.X86_REG_RSI, uc.X86_REG_RDX, uc.X86_REG_R10, uc.X86_REG_R8, uc.X86_REG_R9}

func AbiInit(u models.Usercorn, syscall func(models.Usercorn)) error {
	_, err := u.HookAdd(uc.HOOK_INSN, func(_ uc.Unicorn) {
		syscall(u)
	}, 1, 0, uc.X86_INS_SYSCALL)
	if err == nil {
		_, err = u.HookAdd(uc.HOOK_INSN, func(_ uc.Unicorn) {
			syscall(u)
		}, 1, 0, uc.X86_INS_SYSENTER)
	}
	return err
}
