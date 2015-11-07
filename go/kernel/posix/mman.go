package posix

import (
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *Kernel) Mmap(addrHint, size uint64, prot int, flags int, fd co.Fd, off co.Off) uint64 {
	addr, _ := k.U.Mmap(addrHint, size)
	if fd > 0 {
		fd2, _ := syscall.Dup(int(fd))
		f := os.NewFile(uintptr(fd2), "")
		f.Seek(int64(off), 0)
		tmp := make([]byte, size)
		n, _ := f.Read(tmp)
		k.U.MemWrite(addr, tmp[:n])
		syscall.Close(fd2)
	}
	return addr
}

func (k *Kernel) Munmap(addr, size uint64) uint64 {
	return 0
}

func (k *Kernel) Mprotect() uint64 {
	return 0
}

func (k *Kernel) Brk(addr uint64) uint64 {
	// TODO: return is Linux specific
	ret, _ := k.U.Brk(addr)
	return ret
}
