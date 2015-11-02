package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/syscalls"
)

func DarwinInit(u models.Usercorn, args, env []string) error {
	exe := u.Exe()
	addr, err := u.PushBytes([]byte(exe + "\x00"))
	if err != nil {
		return err
	}
	var tmp [16]byte
	_, err = u.PackAddr(tmp[8:], addr)
	if err != nil {
		return err
	}
	err = AbiInit(u, args, env, tmp[:], DarwinSyscall)
	if err != nil {
		return err
	}
	// offset to exe[0:] in guest memory
	textOffset, _, _ := u.Loader().Header()
	offset := u.Base() + textOffset
	_, err = u.Push(offset)
	return err
}

var darwinOverrides = map[string]*syscalls.Syscall{
	"task_self_trap":                  {syscalls.Stub, A{}, INT},
	"mach_reply_port":                 {syscalls.Stub, A{}, INT},
	"__thread_selfid":                 {syscalls.Stub, A{}, INT},
	"kernelrpc_mach_vm_allocate_trap": {syscalls.Stub, A{}, INT},
}

func DarwinSyscall(u models.Usercorn) {
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Darwin_x86_mach[int(rax)]
	override, _ := darwinOverrides[name]
	ret, _ := u.Syscall(int(rax), name, syscalls.RegArgs(u, AbiRegs), override)
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Init: DarwinInit, Interrupt: DarwinInterrupt})
}
