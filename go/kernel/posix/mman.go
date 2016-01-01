package posix

import (
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *PosixKernel) Mmap(addrHint, size uint64, prot, flags int, fd co.Fd, off co.Off) uint64 {
	// TODO: MAP_FIXED means abort if we can't get the address
	mmap, err := k.U.Mmap(addrHint, size)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	if fd > 0 {
		path, err := PathFromFd(int(fd))
		fd2, _ := syscall.Dup(int(fd))
		f := os.NewFile(uintptr(fd2), path)
		// register mapped files for symbolication of mapped shared libraries
		if err == nil {
			k.U.RegisterAddr(f, mmap.Addr, size, int64(off))
		}
		tmp := make([]byte, size)
		n, _ := f.ReadAt(tmp, int64(off))
		k.U.MemWrite(mmap.Addr, tmp[:n])
		syscall.Close(fd2)
	}
	// currently just trusting protection enums between Unicorn/kernel to match
	k.U.MemProtect(mmap.Addr, size, prot)
	return mmap.Addr
}

func (k *PosixKernel) Mmap2(addrHint, size uint64, prot, flags int, fd co.Fd, off co.Off) uint64 {
	return k.Mmap(addrHint, size, prot, flags, fd, off)
}

func (k *PosixKernel) Munmap(addr, size uint64) uint64 {
	return 0
}

func (k *PosixKernel) Mprotect(addr, size uint64, prot int) uint64 {
	if err := k.U.MemProtect(addr, size, prot); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Brk(addr uint64) uint64 {
	// TODO: return is Linux specific
	ret, _ := k.U.Brk(addr)
	return ret
}
