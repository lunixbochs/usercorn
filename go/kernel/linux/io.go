package linux

import (
	"github.com/lunixbochs/struc"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

const UINT64_MAX = 0xFFFFFFFFFFFFFFFF

func (k *LinuxKernel) getdents(dirfd co.Fd, buf co.Obuf, count uint64, bits uint) uint64 {
	dir, ok := k.Files[dirfd]
	if !ok {
		return UINT64_MAX // FIXME
	}
	dents, err := ioutil.ReadDir(dir.Path)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	if dir.Offset >= uint64(len(dents)) {
		return 0
	}
	dents = dents[dir.Offset:]
	written := 0
	offset := dir.Offset
	for i, f := range dents {
		// TODO: syscall.Stat_t portability?
		inode := f.Sys().(*syscall.Stat_t).Ino
		// figure out file mode
		mode := f.Mode()
		fileType := DT_REG
		if f.IsDir() {
			fileType = DT_DIR
		} else if mode&os.ModeNamedPipe > 0 {
			fileType = DT_FIFO
		} else if mode&os.ModeSymlink > 0 {
			fileType = DT_LNK
		} else if mode&os.ModeDevice > 0 {
			if mode&os.ModeCharDevice > 0 {
				fileType = DT_CHR
			} else {
				fileType = DT_BLK
			}
		} else if mode&os.ModeSocket > 0 {
			fileType = DT_SOCK
		}
		// TODO: does inode get truncated? I guess there's getdents64
		var ent interface{}
		if bits == 64 {
			ent = &Dirent64{inode, dir.Offset + uint64(i), 0, fileType, f.Name() + "\x00"}
		} else {
			ent = &Dirent{inode, dir.Offset + uint64(i), 0, f.Name() + "\x00", fileType}
		}
		size, _ := struc.Sizeof(ent)
		if uint64(written+size) > count {
			break
		}
		offset++
		if k.U.Bits() == 64 {
			ent.(*Dirent64).Len = size
		} else {
			ent.(*Dirent).Len = size
		}
		written += size
		if err := buf.Pack(ent); err != nil {
			return UINT64_MAX // FIXME
		}
	}
	dir.Offset = offset
	return uint64(written)
}

func (k *LinuxKernel) Getdents(dirfd co.Fd, buf co.Obuf, count uint64) uint64 {
	return k.getdents(dirfd, buf, count, k.U.Bits())
}

func (k *LinuxKernel) Getdents64(dirfd co.Fd, buf co.Obuf, count uint64) uint64 {
	return k.getdents(dirfd, buf, count, 64)
}

func (k *LinuxKernel) Sendfile(out, in co.Fd, off co.Buf, count uint64) uint64 {
	// TODO: the in_fd argument must correspond to a file which supports mmap(2)-like operations (i.e., it cannot be a socket).
	outFile := out.File()
	inFile := in.File()
	var offset struc.Off_t
	if off.Addr != 0 {
		if err := off.Unpack(&offset); err != nil {
			return UINT64_MAX // FIXME
		}
	}
	written, err := io.CopyN(outFile, inFile, int64(count))
	// TODO: is EOF handling correct here?
	if (err != nil && err != io.EOF) || written < 0 {
		return UINT64_MAX // FIXME
	}
	return uint64(written)
}
