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
	var tmp [8]byte
	auxv, err := u.PackAddr(tmp[:], addr)
	if err != nil {
		return err
	}
	err = AbiInit(u, args, env, auxv, DarwinSyscall)
	if err != nil {
		return err
	}
	// offset to mach_header at exe[0:] in guest memory
	textOffset, _, _ := u.Loader().Header()
	offset := u.Base() + textOffset
	_, err = u.Push(offset)
	return err
}

func mach_vm_allocate(u syscalls.U, a []uint64) uint64 {
	addr, err := u.Mmap(0, a[2])
	if err != nil {
		return syscalls.UINT64_MAX // FIXME
	}
	var tmp [8]byte
	buf, _ := u.PackAddr(tmp[:], addr)
	if err := u.MemWrite(a[1], buf); err != nil {
		return syscalls.UINT64_MAX // FIXME
	}
	return 0
}

func mach_vm_deallocate(u syscalls.U, a []uint64) uint64 {
	return 0
}

func task_self_trap(u syscalls.U, a []uint64) uint64 {
	return 1
}

func mach_reply_port(u syscalls.U, a []uint64) uint64 {
	return 1
}

func thread_selfid(u syscalls.U, a []uint64) uint64 {
	return 1
}

func thread_fast_set_cthread_self(u syscalls.U, a []uint64) uint64 {
	u.RegWrite(uc.X86_REG_GS, a[0])
	return 0
}

// verifies a binary signature
func csops(u syscalls.U, a []uint64) uint64 {
	return 0
}

func issetugid(u syscalls.U, a []uint64) uint64 {
	return 0
}

func host_self_trap(u syscalls.U, a []uint64) uint64 {
	return 2
}

func mach_msg_trap(u syscalls.U, a []uint64) uint64 {
	return 0
}

var darwinOverrides = map[string]*syscalls.Syscall{
	"task_self_trap":                    {task_self_trap, A{}, INT},
	"mach_reply_port":                   {mach_reply_port, A{}, INT},
	"__thread_selfid":                   {thread_selfid, A{}, INT},
	"kernelrpc_mach_vm_allocate_trap":   {mach_vm_allocate, A{INT, INT, INT, INT}, INT},
	"kernelrpc_mach_vm_deallocate_trap": {mach_vm_deallocate, A{INT, INT, INT}, INT},
	"thread_fast_set_cthread_self":      {thread_fast_set_cthread_self, A{PTR}, INT},
	"csops":          {csops, A{}, INT},
	"issetugid":      {issetugid, A{}, INT},
	"host_self_trap": {host_self_trap, A{}, INT},
	"mach_msg_trap":  {mach_msg_trap, A{}, INT},
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
