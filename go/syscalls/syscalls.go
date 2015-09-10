package syscalls

import (
	"fmt"
	"github.com/lunixbochs/struc"
	"os"
	"syscall"

	"../models"
)

func errno(err error) uint64 {
	if err != nil {
		return ^uint64(err.(syscall.Errno))
	}
	return 0
}

type U models.Usercorn

type Syscall struct {
	Func func(u U, a []uint64) uint64
	Args []int
	Ret  int
}

func exit(u U, a []uint64) uint64 {
	code := int(a[0])
	syscall.Exit(code)
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
	path, _ := u.MemReadStr(a[0])
	mode, flags := int(a[1]), uint32(a[2])
	fd, _ := syscall.Open(path, mode, flags)
	return uint64(fd)
}

func _close(u U, a []uint64) uint64 {
	fd := int(a[0])
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
	err := syscall.Fstat(fd, &stat)
	if err != nil {
		return 1
	}
	err = struc.Pack(u.MemWriter(buf), &stat)
	if err != nil {
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
	path, _ := u.MemReadStr(a[0])
	amode := uint32(a[1])
	err := syscall.Access(path, amode)
	return errno(err)
}

func readv(u U, a []uint64) uint64 {
	fd, iov, count := int(a[0]), a[1], a[2]
	for vec := range iovecIter(u.MemReader(iov), count, int(u.Bits()), u.ByteOrder()) {
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
	for vec := range iovecIter(u.MemReader(iov), count, int(u.Bits()), u.ByteOrder()) {
		data, _ := u.MemRead(vec.Base, vec.Len)
		syscall.Write(fd, data)
	}
	return 0
}

type A []int

var syscalls = map[string]Syscall{
	"exit": {exit, A{INT}, INT},
	// "fork": {fork, A{}, INT},
	"read":     {read, A{FD, OBUF, LEN}, INT},
	"write":    {write, A{FD, BUF, LEN}, INT},
	"open":     {open, A{STR, INT, INT}, FD},
	"close":    {_close, A{FD}, INT},
	"lseek":    {lseek, A{FD, OFF, INT}, INT},
	"mmap":     {mmap, A{PTR, LEN, INT, INT, FD, OFF}, PTR},
	"munmap":   {munmap, A{PTR, LEN}, INT},
	"mprotect": {mprotect, A{PTR, LEN, INT}, INT},
	"brk":      {brk, A{PTR}, PTR},
	"fstat":    {fstat, A{FD, PTR}, INT},
	"getcwd":   {getcwd, A{PTR, LEN}, INT},
	"access":   {access, A{STR, INT}, INT},
	"readv":    {readv, A{FD, PTR, INT}, INT},
	"writev":   {writev, A{FD, PTR, INT}, INT},
}

func Call(u models.Usercorn, num int, name string, getArgs func(n int) ([]uint64, error), strace bool) (uint64, error) {
	s, ok := syscalls[name]
	if !ok {
		panic(fmt.Errorf("Unknown syscall: %s", name))
	}
	args, err := getArgs(len(s.Args))
	if err != nil {
		return 0, err
	}
	if strace {
		Trace(u, name, args)
	}
	ret := s.Func(u, args)
	if strace {
		TraceRet(u, name, args, ret)
	}
	return ret, nil
}
