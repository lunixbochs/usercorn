package vlinux

import (
	"log"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models/cpu"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

// Brk syscall
func (k *VirtualLinuxKernel) Brk(addr uint64) uint64 {
	ret, _ := k.U.Brk(addr)
	return ret
}

// Mmap syscall
func (k *VirtualLinuxKernel) Mmap(addrHint, size uint64, prot enum.MmapProt, flags enum.MmapFlag, fd co.Fd, off co.Off) uint64 {
	// TODO: how do we request an enum lookup from the current kernel?
	MapFixed := enum.MmapFlag(0x10) // on OS X and Linux anyway
	// TODO: MAP_FIXED means abort if we can't get the address
	var (
		data     []byte
		fileDesc *cpu.FileDesc
	)
	// if there's a file descriptor, map (copy for now) the file here before messing with guest memory
	if fd > 0 {
		fd2, ok := k.Fds[fd]
		if !ok {
			log.Printf("Invalid mmap of fd %d", fd)
			return MinusOne
		}
		fileDesc = &cpu.FileDesc{Name: fd2.File.Path, Off: uint64(off), Len: size}
		if size > uint64(len(fd2.File.Data)) {
			size = uint64(len(fd2.File.Data))
		}
		data = fd2.File.Data[:size]
	}
	fixed := flags&MapFixed != 0
	if addrHint == 0 && !fixed {
		// don't automap memory within 8MB of the current program break
		brk, _ := k.U.Brk(0)
		addrHint = brk + 0x800000
	}
	addr, err := k.U.Mmap(addrHint, size, int(prot), fixed, "mmap", fileDesc)
	if err != nil {
		return MinusOne
	}
	if fd > 0 && data != nil {
		err := k.U.MemWrite(addr, data)
		if err != nil {
			return MinusOne
		}
	}
	return addr
}
