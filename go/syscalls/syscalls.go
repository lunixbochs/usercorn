package syscalls

import (
	"fmt"
	"github.com/lunixbochs/struc"
	"os"
	"strings"
	"syscall"

	"github.com/lunixbochs/usercorn/go/models"
)

func errno(err error) uint64 {
	if err != nil {
		return uint64(err.(syscall.Errno))
	}
	return 0
}

const (
	UINT64_MAX = 0xFFFFFFFFFFFFFFFF
)

type U models.Usercorn

type Syscall struct {
	Func func(u U, a []uint64) uint64
	Args []int
	Ret  int
}

func exit(u U, a []uint64) uint64 {
	code := int(a[0])
	u.Exit(code)
	return 0
}

func read(u U, a []uint64) uint64 {
	fd, buf, size := int(a[0]), a[1], a[2]
	tmp := make([]byte, size)
	n, _ := syscall.Read(fd, tmp)
	u.MemWrite(buf, tmp[:n])
	return uint64(n)
}

func write(u U, a []uint64) uint64 {
	fd, buf, size := int(a[0]), a[1], a[2]
	mem, _ := u.MemRead(buf, size)
	n, _ := syscall.Write(fd, mem)
	return uint64(n)
}

func open(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	if strings.Contains(path, "/lib/") {
		path = u.PrefixPath(path, false)
	}
	mode, flags := int(a[1]), uint32(a[2])
	fd, _ := syscall.Open(path, mode, flags)
	return uint64(fd)
}

func _close(u U, a []uint64) uint64 {
	fd := int(a[0])
	// FIXME: temporary hack to preserve output on program exit
	if fd == 2 {
		return 0
	}
	syscall.Close(fd)
	return 0
}

func lseek(u U, a []uint64) uint64 {
	fd, offset, whence := int(a[0]), int64(a[1]), int(a[2])
	off, _ := syscall.Seek(fd, offset, whence)
	return uint64(off)
}

func mmap(u U, a []uint64) uint64 {
	addr_hint, size, prot, flags, fd, off := a[0], a[1], a[2], a[3], int(int32(a[4])), int64(a[5])
	prot, flags = flags, prot // ignore go error
	addr, _ := u.Mmap(addr_hint, size)
	if fd > 0 {
		fd2, _ := syscall.Dup(fd)
		f := os.NewFile(uintptr(fd2), "")
		f.Seek(off, 0)
		tmp := make([]byte, size)
		n, _ := f.Read(tmp)
		u.MemWrite(addr, tmp[:n])
	}
	return uint64(addr)
}

func munmap(u U, a []uint64) uint64 {
	return 0
}

func mprotect(u U, a []uint64) uint64 {
	return 0
}

func brk(u U, a []uint64) uint64 {
	// TODO: return is Linux specific
	addr := a[0]
	ret, _ := u.Brk(addr)
	return ret
}

func fstat(u U, a []uint64) uint64 {
	fd, buf := int(a[0]), a[1]
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return errno(err)
	}
	targetStat := NewTargetStat(&stat, u.OS(), u.Bits())
	if err := struc.PackWithOrder(u.Mem().StreamAt(buf), targetStat, u.ByteOrder()); err != nil {
		panic(err)
	}
	return 0
}

func stat(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	if strings.Contains(path, "/lib/") {
		path = u.PrefixPath(path, false)
	}
	buf := a[1]
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return errno(err)
	}
	targetStat := NewTargetStat(&stat, u.OS(), u.Bits())
	if err := struc.PackWithOrder(u.Mem().StreamAt(buf), targetStat, u.ByteOrder()); err != nil {
		panic(err)
	}
	return 0
}

func getcwd(u U, a []uint64) uint64 {
	buf, size := a[0], a[1]
	wd, _ := os.Getwd()
	if uint64(len(wd)) > size {
		wd = wd[:size]
	}
	u.MemWrite(buf, []byte(wd))
	return 0
}

func access(u U, a []uint64) uint64 {
	// TODO: portability
	path, _ := u.Mem().ReadStrAt(a[0])
	amode := uint32(a[1])
	err := syscall.Access(path, amode)
	return errno(err)
}

func readv(u U, a []uint64) uint64 {
	fd, iov, count := int(a[0]), a[1], a[2]
	for vec := range iovecIter(u.Mem().StreamAt(iov), count, int(u.Bits()), u.ByteOrder()) {
		tmp := make([]byte, vec.Len)
		n, _ := syscall.Read(fd, tmp)
		if n <= 0 {
			break
		}
		u.MemWrite(vec.Base, tmp[:n])
	}
	return 0
}

func writev(u U, a []uint64) uint64 {
	fd, iov, count := int(a[0]), a[1], a[2]
	for vec := range iovecIter(u.Mem().StreamAt(iov), count, int(u.Bits()), u.ByteOrder()) {
		data, _ := u.MemRead(vec.Base, vec.Len)
		syscall.Write(fd, data)
	}
	return 0
}

func getuid(u U, a []uint64) uint64 {
	return uint64(os.Getuid())
}

func getgid(u U, a []uint64) uint64 {
	return uint64(os.Getgid())
}

func geteuid(u U, a []uint64) uint64 {
	return uint64(os.Geteuid())
}

func getegid(u U, a []uint64) uint64 {
	return uint64(os.Getegid())
}

func dup2(u U, a []uint64) uint64 {
	return errno(syscall.Dup2(int(a[0]), int(a[1])))
}

func readlink(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	// TODO: full proc emulation layer
	// maybe have a syscall pre-hook for this after ghostrace makes it generic
	// or specifically have path hooks and use that to implement prefix as well
	bufsz := a[2]
	var name string
	var err error
	if path == "/proc/self/exe" && u.OS() == "linux" {
		name = u.Exe()
	} else {
		name, err = os.Readlink(path)
		if err != nil {
			return UINT64_MAX
		}
	}
	if len(name) > int(bufsz)-1 {
		name = name[:bufsz-1]
	}
	u.Mem().WriteAt([]byte(name+"\x00"), a[1])
	return uint64(len(name))
}

func openat(u U, a []uint64) uint64 {
	dirfd := int(a[0])
	path, _ := u.Mem().ReadStrAt(a[1])
	// TODO: flags might be different per arch
	flags, mode := int(a[2]), uint32(a[3])
	return openat_native(dirfd, path, flags, mode)
}

func Stub(u U, a []uint64) uint64 {
	return 0
}

type A []int

var syscalls = map[string]Syscall{
	"exit":       {exit, A{INT}, INT},
	"exit_group": {exit, A{INT}, INT},
	// "fork": {fork, A{}, INT},
	"read":     {read, A{FD, OBUF, LEN}, INT},
	"write":    {write, A{FD, BUF, LEN}, INT},
	"open":     {open, A{STR, INT, INT}, FD},
	"close":    {_close, A{FD}, INT},
	"lseek":    {lseek, A{FD, OFF, INT}, INT},
	"mmap":     {mmap, A{PTR, LEN, INT, INT, FD, OFF}, PTR},
	"mmap2":    {mmap, A{PTR, LEN, INT, INT, FD, OFF}, PTR},
	"munmap":   {munmap, A{PTR, LEN}, INT},
	"mprotect": {mprotect, A{PTR, LEN, INT}, INT},
	"brk":      {brk, A{PTR}, PTR},
	"fstat":    {fstat, A{FD, PTR}, INT},
	"stat":     {fstat, A{STR, PTR}, INT},
	"getcwd":   {getcwd, A{PTR, LEN}, INT},
	"access":   {access, A{STR, INT}, INT},
	"readv":    {readv, A{FD, PTR, INT}, INT},
	"writev":   {writev, A{FD, PTR, INT}, INT},
	"getuid":   {getuid, A{}, INT},
	"getgid":   {getgid, A{}, INT},
	"geteuid":  {geteuid, A{}, INT},
	"getegid":  {getegid, A{}, INT},
	"dup2":     {dup2, A{INT, INT}, INT},
	"readlink": {readlink, A{STR, OBUF, INT}, LEN},
	"openat":   {openat, A{FD, STR, INT, INT}, FD},

	// stubs
	"ioctl":          {Stub, A{}, INT},
	"rt_sigprocmask": {Stub, A{}, INT},
}

type argFunc func(n int) ([]uint64, error)

func Call(u models.Usercorn, num int, name string, getArgs argFunc, strace bool, override interface{}) (uint64, error) {
	s, ok := syscalls[name]
	if override != nil && override.(*Syscall) != nil {
		s = *override.(*Syscall)
	} else if !ok {
		panic(fmt.Errorf("Unknown syscall: %s", name))
	}
	args, err := getArgs(len(s.Args))
	if err != nil {
		return 0, err
	}
	if strace {
		s.Trace(u, name, args)
	}
	ret := s.Func(u, args)
	if strace {
		s.TraceRet(u, name, args, ret)
	}
	return ret, nil
}
