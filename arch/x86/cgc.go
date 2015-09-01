package x86

import (
	"crypto/rand"
	uc "github.com/lunixbochs/unicorn"
	"syscall"

	"../../models"
)

func writeAddr(u models.Usercorn, addr, val uint64) {
	var buf [4]byte
	u.PackAddr(buf[:], val)
	u.MemWrite(addr, buf[:])
}

func CgcSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	args, _ := u.ReadRegs(LinuxRegs)
	eax, _ := u.RegRead(uc.UC_X86_REG_EAX)
	var ret uint64
	switch eax {
	case 1: // _terminate
		syscall.Exit(int(args[0]))
	case 2: // transmit
		mem, _ := u.MemRead(args[1], args[2])
		n, _ := syscall.Write(int(args[0]), mem)
		writeAddr(u, args[3], uint64(n))
	case 3: // receive
		tmp := make([]byte, args[2])
		n, _ := syscall.Read(int(args[0]), tmp)
		u.MemWrite(args[1], tmp[:n])
		writeAddr(u, args[3], uint64(n))
	case 5: // allocate
		addr, _ := u.Mmap(0, args[0])
		// args[1] == is executable
		writeAddr(u, args[2], addr)
	case 7: // random
		tmp := make([]byte, args[1])
		rand.Read(tmp)
		u.MemWrite(args[0], tmp)
		writeAddr(u, args[2], args[1])
	}
	u.RegWrite(uc.UC_X86_REG_EAX, ret)
}

func CgcInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		CgcSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "cgc", Syscall: CgcSyscall, Interrupt: CgcInterrupt})
}
