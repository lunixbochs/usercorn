package posix

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

func (k *PosixKernel) Mmap(addrHint, size uint64, prot enum.MmapProt, flags enum.MmapFlag, fd co.Fd, off co.Off) uint64 {
	// TODO: how do we request an enum lookup from the current kernel?
	MAP_FIXED := enum.MmapFlag(0x10) // on OS X and Linux anyway
	// TODO: MAP_FIXED means abort if we can't get the address
	var (
		data []byte
		path string
		err  error
		mmap *models.Mmap

		file *os.File
	)
	// if there's a file descriptor, map (copy for now) the file here before messing with guest memory
	if fd > 0 {
		fd2, _ := syscall.Dup(int(fd))
		if file, ok := k.Files[fd]; ok {
			path = file.Path
		}
		if path != "" {
			file = os.NewFile(uintptr(fd2), path)
			defer file.Close()
		}

		data = make([]byte, size)
		var pos uint64
		for pos < size {
			n, err := file.ReadAt(data[pos:], int64(off)+int64(pos))
			pos += uint64(n)
			if err == io.EOF {
				break
			} else if err != nil {
				return UINT64_MAX // FIXME
			}
		}
		data = data[:pos]
	}
	// reserve guest memory (doesn't allocate it yet)
	if flags&MAP_FIXED != 0 {
		mmap, err = k.U.MemReserve(addrHint, size, true)
	} else {
		mmap, err = k.U.MemReserve(addrHint, size, false)
	}
	// map and protect if allocation succeeded
	if err == nil {
		err = k.U.MemMapProt(mmap.Addr, mmap.Size, int(prot))
	}
	if err != nil {
		return UINT64_MAX // FIXME
	}
	if fd > 0 && data != nil {
		k.U.MemWrite(mmap.Addr, data)
		if path != "" {
			// register mapped files for symbolication of mapped shared libraries
			k.U.RegisterFile(file, mmap.Addr, size, int64(off))
		}
	}
	// TODO: don't think we need to protect twice?
	// currently just trusting protection enums between Unicorn/kernel to match
	k.U.MemProtect(mmap.Addr, size, int(prot))
	return mmap.Addr
}

func (k *PosixKernel) Mmap2(addrHint, size uint64, prot enum.MmapProt, flags enum.MmapFlag, fd co.Fd, off co.Off) uint64 {
	return k.Mmap(addrHint, size, prot, flags, fd, off)
}

func (k *PosixKernel) Munmap(addr, size uint64) uint64 {
	return 0
}

func (k *PosixKernel) Mprotect(addr, size uint64, prot enum.MmapProt) uint64 {
	// FIXME: Issue #137
	prot = enum.MmapProt(uc.PROT_ALL)
	if err := k.U.MemProtect(addr, size, int(prot)); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Brk(addr uint64) uint64 {
	// TODO: return is Linux specific
	ret, _ := k.U.Brk(addr)
	return ret
}
