package posix

import (
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *PosixKernel) Mmap(addrHint, size uint64, prot, flags int, fd co.Fd, off co.Off) uint64 {
	// TODO: MAP_FIXED means abort if we can't get the address
	addr, _ := k.U.Mmap(addrHint, size)
	if fd > 0 {
		path, err := PathFromFd(int(fd))
		fd2, _ := syscall.Dup(int(fd))
		f := os.NewFile(uintptr(fd2), path)
		// register mapped files for symbolication of mapped shared libraries
		if err == nil {
			k.U.RegisterAddr(f, addr, size, int64(off))
		}
		tmp := make([]byte, size)
		n, _ := f.ReadAt(tmp, int64(off))
		k.U.MemWrite(addr, tmp[:n])
		syscall.Close(fd2)
	}
	return addr
}

func (k *PosixKernel) Mmap2(addrHint, size uint64, prot, flags int, fd co.Fd, off co.Off) uint64 {
	return k.Mmap(addrHint, size, prot, flags, fd, off)
}

func (k *PosixKernel) Munmap(addr, size uint64) uint64 {
	return 0
}

func (k *PosixKernel) Mprotect() uint64 {
	return 0
}

func (k *PosixKernel) Brk(addr uint64) uint64 {
	// TODO: return is Linux specific
	ret, _ := k.U.Brk(addr)
	return ret
}
