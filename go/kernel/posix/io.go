package posix

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

func (k *PosixKernel) Read(fd co.Fd, buf co.Obuf, size co.Len) uint64 {
	tmp := make([]byte, size)
	n, err := syscall.Read(int(fd), tmp)
	if err != nil {
		return Errno(err)
	}
	if err := buf.Pack(tmp[:n]); err != nil {
		return UINT64_MAX // FIXME
	}
	return uint64(n)
}

func (k *PosixKernel) Write(fd co.Fd, buf co.Buf, size co.Len) uint64 {
	tmp := make([]byte, size)
	if err := buf.Unpack(tmp); err != nil {
		return UINT64_MAX // FIXME
	}
	n, err := syscall.Write(int(fd), tmp)
	if err != nil {
		return Errno(err)
	}
	return uint64(n)
}

func (k *PosixKernel) Open(path string, flags enum.OpenFlag, mode uint64) uint64 {
	// TODO: flags might be different per arch
	if strings.HasPrefix(path, "/") {
		path = k.U.PrefixPath(path, false)
	}
	fd, err := syscall.Open(path, int(flags), uint32(mode))
	if err != nil {
		/*
			k.U.Trampoline(func() error {
				eflags, err := k.U.RegRead(uc.X86_REG_EFLAGS)

				const CF uint64 = 1 << 0
				eflags |= CF //set carry flag

				err = k.U.RegWrite(uc.X86_REG_EFLAGS, eflags)
				return err
			})
		*/
		return Errno(err)
	}
	path, _ = filepath.Abs(path)
	k.Files[co.Fd(fd)] = &File{
		Fd:    co.Fd(fd),
		Path:  path,
		Flags: int(flags),
		Mode:  int(mode),
	}
	return uint64(fd)
}

func (k *PosixKernel) Openat(dirfd co.Fd, path string, flags enum.OpenFlag, mode uint64) uint64 {
	// FIXME: AT_FDCWD == -100 on Linux, but this is Posix
	if !strings.HasPrefix(path, "/") && dirfd != -100 {
		if dir, ok := k.Files[dirfd]; ok {
			path = filepath.Join(dir.Path, path)
		} else {
			return UINT64_MAX // FIXME
		}
	}
	return k.Open(path, flags, mode)
}

func (k *PosixKernel) Close(fd co.Fd) uint64 {
	// FIXME: temporary hack to preserve output on program exit
	if fd == 2 {
		return 0
	}
	delete(k.Files, fd)
	return Errno(syscall.Close(int(fd)))
}

func (k *PosixKernel) Lseek(fd co.Fd, offset co.Off, whence int) uint64 {
	off, err := syscall.Seek(int(fd), int64(offset), whence)
	if err != nil {
		return Errno(err)
	}
	return uint64(off)
}

func (k *PosixKernel) Fstat(fd co.Fd, buf co.Obuf) uint64 {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(fd), &stat); err != nil {
		return Errno(err)
	}
	targetStat := NewTargetStat(&stat, k.U.OS(), k.U.Bits())
	if err := buf.Pack(targetStat); err != nil {
		panic(err)
	}
	return 0
}

func (k *PosixKernel) Lstat(path string, buf co.Obuf) uint64 {
	var stat syscall.Stat_t
	if err := syscall.Lstat(path, &stat); err != nil {
		return Errno(err)
	}
	targetStat := NewTargetStat(&stat, k.U.OS(), k.U.Bits())
	if err := buf.Pack(targetStat); err != nil {
		panic(err)
	}
	return 0
}

func (k *PosixKernel) Stat(path string, buf co.Obuf) uint64 {
	// TODO: centralize path hook
	if strings.HasPrefix(path, "/") {
		path = k.U.PrefixPath(path, false)
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return Errno(err)
	}
	targetStat := NewTargetStat(&stat, k.U.OS(), k.U.Bits())
	if err := buf.Pack(targetStat); err != nil {
		panic(err)
	}
	return 0
}

func (k *PosixKernel) Getcwd(buf co.Obuf, size co.Len) uint64 {
	wd, _ := os.Getwd()
	size -= 1
	if co.Len(len(wd)) > size {
		wd = wd[:size]
	}
	if err := buf.Pack(wd + "\x00"); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Access(path string, amode uint32) uint64 {
	// TODO: portability
	return Errno(syscall.Access(path, amode))
}

func (k *PosixKernel) Readv(fd co.Fd, iov co.Buf, count uint64) uint64 {
	var read uint64
	for vec := range iovecIter(iov, count, k.U.Bits()) {
		tmp := make([]byte, vec.Len)
		n, err := syscall.Read(int(fd), tmp)
		if err != nil {
			return Errno(err)
		}
		read += uint64(n)
		k.U.MemWrite(vec.Base, tmp[:n])
	}
	return read
}

func (k *PosixKernel) Writev(fd co.Fd, iov co.Buf, count uint64) uint64 {
	var written uint64
	for vec := range iovecIter(iov, count, k.U.Bits()) {
		data, _ := k.U.MemRead(vec.Base, vec.Len)
		n, err := syscall.Write(int(fd), data)
		if err != nil {
			return Errno(err)
		}
		written += uint64(n)
	}
	return written
}

func (k *PosixKernel) Pread64(fd co.Fd, buf co.Obuf, size co.Len, offset int64) uint64 {
	p := make([]byte, size)
	n, err := syscall.Pread(int(fd), p, offset)
	if err != nil {
		return Errno(err)
	}
	if err := buf.Pack(p); err != nil {
		return UINT64_MAX // FIXME
	}
	return uint64(n)
}

func (k *PosixKernel) Pwrite64(fd co.Fd, buf co.Buf, size co.Len, offset int64) uint64 {
	p := make([]byte, size)
	if err := buf.Unpack(p); err != nil {
		return UINT64_MAX // FIXME
	}
	n, err := syscall.Pwrite(int(fd), p, offset)
	if err != nil {
		return Errno(err)
	}
	return uint64(n)
}

func (k *PosixKernel) Chmod(path string, mode uint32) uint64 {
	return Errno(syscall.Chmod(path, mode))
}

func (k *PosixKernel) Fchmod(fd int, mode uint32) uint64 {
	return Errno(syscall.Fchmod(fd, mode))
}

func (k *PosixKernel) Chown(path string, uid, gid int) uint64 {
	return Errno(syscall.Chown(path, uid, gid))
}

func (k *PosixKernel) Fchown(fd, uid, gid int) uint64 {
	return Errno(syscall.Fchown(fd, uid, gid))
}

func (k *PosixKernel) Lchown(path string, uid, gid int) uint64 {
	return Errno(syscall.Lchown(path, uid, gid))
}

func (k *PosixKernel) Dup(oldFd co.Fd) uint64 {
	if newFd, err := syscall.Dup(int(oldFd)); err != nil {
		return Errno(err)
	} else {
		return uint64(newFd)
	}
}

func (k *PosixKernel) Dup2(oldFd co.Fd, newFd co.Fd) uint64 {
	if err := syscall.Dup2(int(oldFd), int(newFd)); err != nil {
		return Errno(err)
	}
	return uint64(newFd)
}

func (k *PosixKernel) Readlink(path string, buf co.Obuf, size co.Len) uint64 {
	// TODO: full proc emulation layer
	// maybe have a syscall pre-hook for this after ghostrace makes it generic
	// or specifically have path hooks and use that to implement prefix as well
	var name string
	var err error
	if path == "/proc/self/exe" && k.U.OS() == "linux" {
		name = k.U.Exe()
	} else {
		name, err = os.Readlink(path)
		if err != nil {
			return UINT64_MAX // FIXME
		}
	}
	if len(name) > int(size) {
		name = name[:size]
	}
	if err := buf.Pack([]byte(name)); err != nil {
		return UINT64_MAX // FIXME
	}
	return uint64(len(name))
}

func (k *PosixKernel) Symlink(src, dst string) uint64 {
	return Errno(syscall.Symlink(src, dst))
}

func (k *PosixKernel) Link(src, dst string) uint64 {
	return Errno(syscall.Link(src, dst))
}

func (k *PosixKernel) Chdir(path string) uint64 {
	if err := os.Chdir(path); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Chroot(path string) uint64 {
	return Errno(syscall.Chroot(path))
}

func (k *PosixKernel) Pipe(files co.Buf) uint64 {
	var fds [2]int
	err := syscall.Pipe(fds[:])
	if err == nil {
		st := files.Struc()
		err := st.Pack(int32(fds[0]))
		if err == nil {
			err = st.Pack(int32(fds[1]))
		}
		if err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return Errno(err)
}

func (k *PosixKernel) Pipe2(files co.Buf, flags int) uint64 {
	// TODO: handle flags
	return k.Pipe(files)
}

func (k *PosixKernel) Unlink(path string) uint64 {
	return Errno(syscall.Unlink(path))
}
