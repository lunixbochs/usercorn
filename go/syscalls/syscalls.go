package syscalls

import (
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
		return uint64(int64(-err.(syscall.Errno)))
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
	n, err := syscall.Read(fd, tmp)
	if err != nil {
		return errno(err)
	}
	u.MemWrite(buf, tmp[:n])
	return uint64(n)
}

func write(u U, a []uint64) uint64 {
	fd, buf, size := int(a[0]), a[1], a[2]
	mem, _ := u.MemRead(buf, size)
	n, err := syscall.Write(fd, mem)
	if err != nil {
		return errno(err)
	}
	return uint64(n)
}

func open(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	if strings.Contains(path, "/lib/") {
		path = u.PrefixPath(path, false)
	}
	mode, flags := int(a[1]), uint32(a[2])
	fd, err := syscall.Open(path, mode, flags)
	if err != nil {
		return errno(err)
	}
	return uint64(fd)
}

func _close(u U, a []uint64) uint64 {
	fd := int(a[0])
	// FIXME: temporary hack to preserve output on program exit
	if fd == 2 {
		return 0
	}
	return errno(syscall.Close(fd))
}

func lseek(u U, a []uint64) uint64 {
	fd, offset, whence := int(a[0]), int64(a[1]), int(a[2])
	off, err := syscall.Seek(fd, offset, whence)
	if err != nil {
		return errno(err)
	}
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
		syscall.Close(fd2)
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
	if err := u.StrucAt(buf).Pack(targetStat); err != nil {
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
	if err := u.StrucAt(buf).Pack(targetStat); err != nil {
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
	if err := u.StrucAt(buf).Pack(targetStat); err != nil {
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
	var read uint64
	for vec := range iovecIter(u.StrucAt(iov), count, u.Bits()) {
		tmp := make([]byte, vec.Len)
		n, err := syscall.Read(fd, tmp)
		if err != nil {
			return errno(err)
		}
		read += uint64(n)
		u.MemWrite(vec.Base, tmp[:n])
	}
	return read
}

func writev(u U, a []uint64) uint64 {
	fd, iov, count := int(a[0]), a[1], a[2]
	var written uint64
	for vec := range iovecIter(u.StrucAt(iov), count, u.Bits()) {
		data, _ := u.MemRead(vec.Base, vec.Len)
		n, err := syscall.Write(fd, data)
		if err != nil {
			return errno(err)
		}
		written += uint64(n)
	}
	return written
}

func chmod(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	mode := uint32(a[1])
	return errno(syscall.Chmod(path, mode))
}

func getegid(u U, a []uint64) uint64 {
	return uint64(os.Getegid())
}

func geteuid(u U, a []uint64) uint64 {
	return uint64(os.Geteuid())
}

func getgid(u U, a []uint64) uint64 {
	return uint64(os.Getgid())
}

func getuid(u U, a []uint64) uint64 {
	return uint64(os.Getuid())
}

func setgid(u U, a []uint64) uint64 {
	// TODO: these don't work on Linux
	syscall.Setgid(int(a[0]))
	return 0
}

func setuid(u U, a []uint64) uint64 {
	// TODO: these don't work on Linux
	syscall.Setuid(int(a[0]))
	return 0
}

func getgroups(u U, a []uint64) uint64 {
	groups, err := syscall.Getgroups()
	if err != nil {
		return UINT64_MAX // FIXME
	}
	length := uint64(len(groups))
	if a[0] > 0 {
		if a[0] < uint64(len(groups)) {
			groups = groups[:a[0]]
		}
		tmp := make([]uint32, len(groups))
		for i, v := range groups {
			tmp[i] = uint32(v)
		}
		err = u.StrucAt(a[1]).Pack(tmp)
		if err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return length
}

func dup2(u U, a []uint64) uint64 {
	if err := syscall.Dup2(int(a[0]), int(a[1])); err != nil {
		return errno(err)
	}
	return a[1]
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

func symlink(u U, a []uint64) uint64 {
	path1, _ := u.Mem().ReadStrAt(a[0])
	path2, _ := u.Mem().ReadStrAt(a[1])
	return errno(syscall.Symlink(path1, path2))
}

func link(u U, a []uint64) uint64 {
	path1, _ := u.Mem().ReadStrAt(a[0])
	path2, _ := u.Mem().ReadStrAt(a[1])
	return errno(syscall.Link(path1, path2))
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
	in := u.StrucAt(a[1])
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
		if err := in.Unpack(ent); err != nil {
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
	out := u.StrucAt(a[1])
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
		size, _ := struc.Sizeof(ent)
		if uint64(written+size) > count {
			break
		}
		if u.Bits() == 64 {
			ent.(*LinuxDirent64).Len = size
		} else {
			ent.(*LinuxDirent).Len = size
		}
		written += size
		if err := out.Pack(ent); err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return uint64(written)
}

func getpid(u U, a []uint64) uint64 {
	return uint64(os.Getpid())
}

func getppid(u U, a []uint64) uint64 {
	return uint64(os.Getppid())
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
	sa := decodeSockaddr(u, sockaddrbuf)
	if sa == nil {
		return UINT64_MAX // FIXME
	}
	return errno(syscall.Connect(fd, sa))
}

func bind(u U, a []uint64) uint64 {
	fd := int(a[0])
	sockaddrbuf, err := u.MemRead(a[1], a[2])
	if err != nil {
		return UINT64_MAX // FIXME
	}
	sa := decodeSockaddr(u, sockaddrbuf)
	if sa == nil {
		return UINT64_MAX // FIXME
	}
	return errno(syscall.Bind(fd, sa))
}

func sendto(u U, a []uint64) uint64 {
	fd := int(a[0])
	msg, err := u.MemRead(a[1], a[2])
	if err != nil {
		return UINT64_MAX
	}
	flags := a[3]
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{}
	if a[4] != 0 {
		sockaddrbuf, err := u.MemRead(a[4], a[5])
		if err != nil {
			return UINT64_MAX // FIXME
		}
		sa = decodeSockaddr(u, sockaddrbuf)
		if sa == nil {
			return UINT64_MAX // FIXME
		}
	}
	return errno(syscall.Sendto(fd, msg, int(flags), sa))
}

func getsockopt(u U, a []uint64) uint64 {
	// TODO: dispatch/support both addr and int types
	fd, level, opt := int(a[0]), int(a[1]), int(a[2])
	value, err := syscall.GetsockoptInt(fd, level, opt)
	if err != nil {
		return errno(err)
	}
	value32 := int32(value)
	size := int32(4)
	u.StrucAt(a[3]).Pack(value32)
	u.StrucAt(a[4]).Pack(size)
	return 0
}

func setsockopt(u U, a []uint64) uint64 {
	// TODO: dispatch/support all setsockopt types
	fd, level, opt, size := int(a[0]), int(a[1]), int(a[2]), int(a[4])
	if size != 4 {
		fmt.Fprintf(os.Stderr, "WARNING: unsupported Setsockopt type %d\n", size)
		return UINT64_MAX // FIXME
	}
	var value int32
	u.StrucAt(a[3]).Unpack(&value)
	if err := syscall.SetsockoptInt(fd, level, opt, opt); err != nil {
		return errno(err)
	}
	return 0
}

func clock_gettime(u U, a []uint64) uint64 {
	var err error
	out := u.StrucAt(a[1])
	ts := syscall.NsecToTimespec(time.Now().UnixNano())
	if u.Bits() == 64 {
		err = out.Pack(&Timespec64{ts.Sec, ts.Nsec})
	} else {
		err = out.Pack(&Timespec{int32(ts.Sec), int32(ts.Nsec)})
	}
	if err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func chdir(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	if err := os.Chdir(path); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func chroot(u U, a []uint64) uint64 {
	path, _ := u.Mem().ReadStrAt(a[0])
	return errno(syscall.Chroot(path))
}

func kill(u U, a []uint64) uint64 {
	// TODO: os-specific signal handling?
	pid, sig := a[0], a[1]
	return errno(syscall.Kill(int(pid), syscall.Signal(sig)))
}

func execve(u U, a []uint64) uint64 {
	// TODO: put this function somewhere generic?
	readStrArray := func(addr uint64) []string {
		var out []string
		stream := u.StrucAt(addr)
		for {
			var addr uint64
			if u.Bits() == 64 {
				stream.Unpack(&addr)
			} else {
				var addr32 uint32
				stream.Unpack(&addr32)
				addr = uint64(addr32)
			}
			if addr == 0 {
				break
			}
			s, _ := u.Mem().ReadStrAt(addr)
			out = append(out, s)
		}
		return out
	}
	path, _ := u.Mem().ReadStrAt(a[0])
	argv := readStrArray(a[1])
	envp := readStrArray(a[2])
	return errno(syscall.Exec(path, argv, envp))
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
	"chmod":    {chmod, A{STR, INT}, INT},

	"getegid":   {getegid, A{}, INT},
	"geteuid":   {geteuid, A{}, INT},
	"getgid":    {getgid, A{}, INT},
	"getuid":    {getuid, A{}, INT},
	"setgid":    {setgid, A{INT}, INT},
	"setuid":    {setuid, A{INT}, INT},
	"getgroups": {getgroups, A{INT, PTR}, INT},

	"dup2":     {dup2, A{INT, INT}, INT},
	"readlink": {readlink, A{STR, OBUF, INT}, LEN},
	"symlink":  {symlink, A{STR, STR}, INT},
	"link":     {link, A{STR, STR}, INT},
	"openat":   {openat, A{FD, STR, INT, INT}, FD},
	"getdents": {getdents, A{FD, OBUF, INT}, LEN},
	"getpid":   {getpid, A{}, INT},
	"getppid":  {getppid, A{}, INT},
	"socket":   {socket, A{INT, INT, INT}, FD},
	"connect":  {connect, A{INT, PTR, LEN}, INT},
	"bind":     {bind, A{INT, PTR, LEN}, INT},
	"sendto":   {sendto, A{FD, PTR, LEN, INT, PTR, LEN}, INT},

	"getsockopt": {getsockopt, A{FD, INT, INT, PTR, PTR}, INT},
	"setsockopt": {setsockopt, A{FD, INT, INT, PTR, INT}, INT},

	"clock_gettime": {clock_gettime, A{INT, PTR}, INT},
	"chdir":         {chdir, A{STR}, INT},
	"chroot":        {chroot, A{STR}, INT},
	"kill":          {kill, A{PID, SIGNAL}, INT},
	"execve":        {execve, A{STR, PTR, PTR}, INT},

	// stubs
	"ioctl":          {Stub, A{}, INT},
	"rt_sigprocmask": {Stub, A{}, INT},
	"rt_sigaction":   {Stub, A{}, INT},
	"futex":          {Stub, A{}, INT},
	"fcntl":          {Stub, A{}, INT},
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
