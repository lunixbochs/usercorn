package syscalls

import (
	"encoding/binary"
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
	Func func(u U, args []uint64) uint64
	Args int
}

func exit(u U, args []uint64) uint64 {
	syscall.Exit(int(args[0]))
	return 0
}

func read(u U, args []uint64) uint64 {
	tmp := make([]byte, args[2])
	n, _ := syscall.Read(int(args[0]), tmp)
	u.MemWrite(args[1], tmp[:n])
	return uint64(n)
}

func write(u U, args []uint64) uint64 {
	mem, _ := u.MemRead(args[1], args[2])
	n, _ := syscall.Write(int(args[0]), mem)
	return uint64(n)
}

func open(u U, args []uint64) uint64 {
	path, _ := u.MemReadStr(args[0])
	fd, _ := syscall.Open(path, int(args[1]), uint32(args[2]))
	return uint64(fd)
}

func _close(u U, args []uint64) uint64 {
	syscall.Close(int(args[0]))
	return 0
}

func lseek(u U, args []uint64) uint64 {
	off, _ := syscall.Seek(int(args[0]), int64(args[1]), int(args[2]))
	return uint64(off)
}

func mmap(u U, args []uint64) uint64 {
	size := args[1]
	addr, _ := u.Mmap(args[0], size)
	fd, off := int(int32(args[4])), int64(args[5])
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

func munmap(u U, args []uint64) uint64 {
	return 0
}

func mprotect(u U, args []uint64) uint64 {
	return 0
}

func brk(u U, args []uint64) uint64 {
	// TODO: return is Linux specific
	ret, _ := u.Brk(args[0])
	return ret
}

func fstat(u U, args []uint64) uint64 {
	var stat syscall.Stat_t
	err := syscall.Fstat(int(args[0]), &stat)
	if err != nil {
		return 1
	}
	err = struc.Pack(u.MemWriter(args[1]), &stat)
	if err != nil {
		panic(err)
	}
	return 0
}

func getcwd(u U, args []uint64) uint64 {
	wd, _ := os.Getwd()
	if uint64(len(wd)) > args[1] {
		wd = wd[:args[1]]
	}
	u.MemWrite(args[0], []byte(wd))
	return 0
}

func access(u U, args []uint64) uint64 {
	// TODO: portability
	path, _ := u.MemReadStr(args[0])
	err := syscall.Access(path, uint32(args[1]))
	return errno(err)
}

func writev(u U, args []uint64) uint64 {
	ptr := u.MemReader(args[1])
	var i uint64
	for i = 0; i < args[2]; i++ {
		// TODO: bits support (via Usercorn.Bits() I think)
		var iovec Iovec64
		// TODO: endian support
		struc.UnpackWithOrder(ptr, &iovec, binary.LittleEndian)
		data, _ := u.MemRead(iovec.Base, iovec.Len)
		syscall.Write(int(args[0]), data)
	}
	return 0
}

var syscalls = map[string]Syscall{
	"exit": {exit, 1},
	// "fork": {fork, 0},
	"read":     {read, 3},
	"write":    {write, 3},
	"open":     {open, 3},
	"close":    {_close, 1},
	"lseek":    {lseek, 3},
	"mmap":     {mmap, 6},
	"munmap":   {munmap, 2},
	"mprotect": {mprotect, 3},
	"brk":      {brk, 1},
	"fstat":    {fstat, 2},
	"getcwd":   {getcwd, 2},
	"access":   {access, 2},
	"writev":   {writev, 3},
}

func Call(u models.Usercorn, name string, getArgs func(n int) ([]uint64, error), strace bool) (uint64, error) {
	s, ok := syscalls[name]
	if !ok {
		panic(fmt.Errorf("Unknown syscall: %s", name))
	}
	args, err := getArgs(s.Args)
	if err != nil {
		return 0, err
	}
	if strace {
		fmt.Println("Syscall", name, args)
	}
	return s.Func(u, args), nil
}
