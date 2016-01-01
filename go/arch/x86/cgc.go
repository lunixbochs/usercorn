package x86

import (
	"crypto/rand"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"syscall"

	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/native"
)

const UINT32_MAX = 0xFFFFFFFF

func writeAddr(u models.Usercorn, addr, val uint64) {
	var buf [4]byte
	u.PackAddr(buf[:], val)
	u.MemWrite(addr, buf[:])
}

func CgcInit(u models.Usercorn, args, env []string) error {
	// TODO: does CGC even specify argv?
	// TODO: also, I seem to remember something about mapping in 16kb of random data
	return posix.StackInit(u, args, env, nil)
}

func CgcSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	args, _ := u.ReadRegs(LinuxRegs)
	eax, _ := u.RegRead(uc.X86_REG_EAX)
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
		mmap, _ := u.Mmap(0, args[0])
		// args[1] == is executable
		writeAddr(u, args[2], mmap.Addr)
	case 6: // fdwait
		nfds := int(args[0])
		var readSet, writeSet *native.Fdset32
		var timeout native.Timespec
		u.StrucAt(args[1]).Unpack(&readSet)
		u.StrucAt(args[2]).Unpack(&writeSet)
		u.StrucAt(args[3]).Unpack(&timeout)
		readyFds := args[4]

		readNative := readSet.Native()
		writeNative := writeSet.Native()
		n, err := native.Select(nfds, readNative, writeNative, &timeout)
		if err != nil {
			ret = UINT32_MAX // FIXME?
		} else {
			numReady := int32(n)
			if readyFds != 0 {
				u.StrucAt(readyFds).Pack(numReady)
			}
		}
	case 7: // random
		tmp := make([]byte, args[1])
		rand.Read(tmp)
		u.MemWrite(args[0], tmp)
		writeAddr(u, args[2], args[1])
	}
	u.RegWrite(uc.X86_REG_EAX, ret)
}

func CgcInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		CgcSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "cgc",
		Init:      CgcInit,
		Interrupt: CgcInterrupt,
	})
}
