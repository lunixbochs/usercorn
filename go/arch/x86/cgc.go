package x86

import (
	"crypto/rand"
	"encoding/binary"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"syscall"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/syscalls"
)

const UINT32_MAX = 0xFFFFFFFF

type fdset32 struct {
	Bits [32]int32
}

func (f *fdset32) Set(fd int) {
	f.Bits[fd/32] |= (1 << (uint(fd) & (32 - 1)))
}

func (f *fdset32) Clear(fd int) {
	f.Bits[fd/32] &= ^(1 << (uint(fd) & (32 - 1)))
}

func (f *fdset32) IsSet(fd int) bool {
	return f.Bits[fd/32]&(1<<(uint(fd)&(32-1))) != 0
}

func (f *fdset32) Fds() []int {
	var out []int
	for fd := 0; fd < 1024; fd++ {
		if f.IsSet(fd) {
			out = append(out, fd)
		}
	}
	return out
}

func writeAddr(u models.Usercorn, addr, val uint64) {
	var buf [4]byte
	u.PackAddr(buf[:], val)
	u.MemWrite(addr, buf[:])
}

func CgcInit(u models.Usercorn, args, env []string) error {
	return u.PosixInit(args, env, nil)
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
		addr, _ := u.Mmap(0, args[0])
		// args[1] == is executable
		writeAddr(u, args[2], addr)
	case 6: // fdwait
		nfds := int(args[0])
		var readSet, writeSet *fdset32
		var timeout syscalls.Timespec
		u.StrucAt(args[1]).Unpack(&readSet)
		u.StrucAt(args[2]).Unpack(&writeSet)
		u.StrucAt(args[3]).Unpack(&timeout)
		readyFds := args[4]

		readNative := readSet.Native()
		writeNative := writeSet.Native()
		n, err := cgcNativeSelect(nfds, readNative, writeNative, &timeout)
		if err != nil {
			ret = UINT32_MAX // FIXME?
		} else {
			numReady := int32(n)
			if readyFds != 0 {
				binary.Write(u.Mem().StreamAt(readyFds), u.ByteOrder(), &numReady)
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
	Arch.RegisterOS(&models.OS{Name: "cgc", Init: CgcInit, Interrupt: CgcInterrupt})
}
