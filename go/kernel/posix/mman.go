package posix

import (
	"io"
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models/cpu"
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
		file *os.File

		fileDesc *cpu.FileDesc
	)
	// if there's a file descriptor, map (copy for now) the file here before messing with guest memory
	if fd > 0 {
		fd2, _ := syscall.Dup(int(fd))
		if file, ok := k.Files[fd]; ok {
			path = file.Path
		}
		if path != "" {
			fileDesc = &cpu.FileDesc{Name: path, Off: uint64(off), Len: size}
			file = os.NewFile(uintptr(fd2), path)
			defer file.Close()
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
	}
	fixed := flags&MAP_FIXED != 0
	if addrHint == 0 && !fixed {
		// don't automap memory within 8MB of the current program break
		brk, _ := k.U.Brk(0)
		addrHint = brk + 0x800000
	}
	addr, err := k.U.Mmap(addrHint, size, int(prot), fixed, "mmap", fileDesc)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	if fd > 0 && data != nil {
		err := k.U.MemWrite(addr, data)
		if err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return addr
}

func (k *PosixKernel) Munmap(addr, size uint64) uint64 {
	// TODO: page size
	if addr&0xfff != 0 {
		return UINT64_MAX // FIXME: EINVAL
	}
	k.U.MemUnmap(addr, size)
	return 0
}

func (k *PosixKernel) Mprotect(addr, size uint64, prot enum.MmapProt) uint64 {
	// FIXME: Issue #137
	prot = enum.MmapProt(cpu.PROT_ALL)
	if err := k.U.MemProt(addr, size, int(prot)); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Mremap(old_addr, old_size, new_size uint64, flags int) uint64 {
	// NOTE: this is a hack
	addr, err := k.U.Mmap(0, new_size, 7, false, "mmap", nil)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	tmp := make([]byte, old_size)
	k.U.MemReadInto(tmp, old_addr)
	k.U.MemWrite(addr, tmp)
	return addr
}

func (k *PosixKernel) Brk(addr uint64) uint64 {
	// TODO: return is Linux specific
	ret, _ := k.U.Brk(addr)
	return ret
}
