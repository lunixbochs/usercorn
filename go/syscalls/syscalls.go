package syscalls

import (
	"bytes"
	"fmt"
	"github.com/lunixbochs/struc"
	"io/ioutil"
	"os"
	"strings"
	// TODO: syscall module is not portable
	"syscall"
	"time"

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
	// TODO: centralize path hook
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

func lstat(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	buf := a[1]
	var stat syscall.Stat_t
	if err := syscall.Lstat(path, &stat); err != nil {
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

func getdents(u U, a []uint64) uint64 {
	dirPath, err := pathFromFd(int(a[0]))
	if err != nil {
		return UINT64_MAX // FIXME
	}
	dents, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	count := a[2]
	// figure out our offset
	// TODO: maybe figure out how the kernel does this
	in := u.Mem().StreamAt(a[1])
	var offset, read uint64
	// TODO: DRY? :(
	var ent interface{}
	if u.Bits() == 64 {
		ent = &LinuxDirent64{}
	} else {
		ent = &LinuxDirent{}
	}
	for {
		tmp := ent.(*LinuxDirent64)
		if err := struc.Unpack(in, ent); err != nil {
			break
		}
		size, _ := struc.Sizeof(ent)
		if read+uint64(size) > count {
			break
		}
		if tmp.Off > 0 {
			offset = tmp.Off
		}
		if tmp.Len == 0 {
			break
		}
	}
	if offset >= uint64(len(dents)) {
		return 0
	}
	out := u.Mem().StreamAt(a[1])
	dents = dents[offset:]
	written := 0
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
		if u.Bits() == 64 {
			ent = &LinuxDirent64{inode, uint64(i), 0, f.Name() + "\x00", fileType}
		} else {
			ent = &LinuxDirent{inode, uint64(i), 0, f.Name() + "\x00", fileType}
		}
		size, err := struc.Sizeof(ent)
		if uint64(written+size) > count {
			break
		}
		if u.Bits() == 64 {
			ent.(*LinuxDirent64).Len = size
		} else {
			ent.(*LinuxDirent).Len = size
		}
		written += size
		err = struc.PackWithOrder(out, ent, u.ByteOrder())
		if err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return uint64(written)
}

func getpid(u U, a []uint64) uint64 {
	return uint64(os.Getpid())
}

func socket(u U, a []uint64) uint64 {
	fd, err := syscall.Socket(int(a[0]), int(a[1]), int(a[2]))
	if err != nil {
		return errno(err)
	}
	return uint64(fd)
}

func connect(u U, a []uint64) uint64 {
	fd := int(a[0])
	sockaddrbuf, err := u.MemRead(a[1], a[2])
	if err != nil {
		return UINT64_MAX // FIXME
	}
	family := u.ByteOrder().Uint16(sockaddrbuf)
	buf := bytes.NewReader(sockaddrbuf)
	var sa syscall.Sockaddr
	switch family {
	case AF_LOCAL:
		var addr RawSockaddrUnix
		struc.Unpack(buf, &addr)
		paths := bytes.SplitN([]byte(addr.Path[:]), []byte{0}, 2)
		sa = &syscall.SockaddrUnix{Name: string(paths[0])}
	case AF_INET:
		var addr syscall.RawSockaddrInet4
		struc.Unpack(buf, &addr)
		// TODO: unfinished
		sa = &syscall.SockaddrInet4{}
	default:
		return UINT64_MAX // FIXME
	}
	return errno(syscall.Connect(fd, sa))
}

func sendto(u U, a []uint64) uint64 {
	// TODO: unfinished
	return UINT64_MAX
}

func clock_gettime(u U, a []uint64) uint64 {
	var err error
	out := u.Mem().StreamAt(a[1])
	ts := syscall.NsecToTimespec(time.Now().UnixNano())
	if u.Bits() == 64 {
		err = struc.Pack(out, &Timespec64{ts.Sec, ts.Nsec})
	} else {
		err = struc.Pack(out, &Timespec{int32(ts.Sec), int32(ts.Nsec)})
	}
	if err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func Stub(u U, a []uint64) uint64 {
	return UINT64_MAX
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
	"stat":     {stat, A{STR, PTR}, INT},
	"lstat":    {lstat, A{STR, PTR}, INT},
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
	"getdents": {getdents, A{FD, OBUF, INT}, LEN},
	"getpid":   {getpid, A{}, INT},
	"socket":   {socket, A{INT, INT, INT}, FD},
	"connect":  {connect, A{INT, PTR, LEN}, INT},
	"sendto":   {sendto, A{FD, PTR, INT, PTR}, INT},

	"clock_gettime": {clock_gettime, A{INT, PTR}, INT},

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
