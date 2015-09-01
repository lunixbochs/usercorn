package x86_64

import (
	uc "github.com/lunixbochs/unicorn"

	"../../models"
	"../../syscalls"
)

var AbiRegs = []int{uc.UC_X86_REG_RDI, uc.UC_X86_REG_RSI, uc.UC_X86_REG_RDX, uc.UC_X86_REG_R10, uc.UC_X86_REG_R8, uc.UC_X86_REG_R9}

func AbiSyscall(u models.Usercorn, table map[int]string) {
	rax, _ := u.RegRead(uc.UC_X86_REG_RAX)
	ret, _ := u.Syscall(table, int(rax), syscalls.RegArgs(u, AbiRegs))
	u.RegWrite(uc.UC_X86_REG_RAX, ret)
}
