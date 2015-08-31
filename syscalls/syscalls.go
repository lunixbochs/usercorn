package syscalls

import (
	"fmt"
	"syscall"

	"../models"
)

type Syscall struct {
	Func func(u models.Usercorn, args []uint64) uint64
	Args int
}

func exit(u models.Usercorn, args []uint64) uint64 {
	syscall.Exit(int(args[0]))
	return 0
}

func read(u models.Usercorn, args []uint64) uint64 {
	tmp := make([]byte, args[2])
	n, _ := syscall.Read(int(args[0]), tmp)
	u.MemWrite(args[1], tmp[:n])
	return uint64(n)
}

func write(u models.Usercorn, args []uint64) uint64 {
	mem, _ := u.MemRead(args[1], args[2])
	n, _ := syscall.Write(int(args[0]), mem)
	return uint64(n)
}

func open(u models.Usercorn, args []uint64) uint64 {
	path, _ := u.MemReadStr(args[0])
	fd, _ := syscall.Open(path, int(args[1]), uint32(args[2]))
	return uint64(fd)
}

func _close(u models.Usercorn, args []uint64) uint64 {
	syscall.Close(int(args[0]))
	return 0
}

func lseek(u models.Usercorn, args []uint64) uint64 {
	off, _ := syscall.Seek(int(args[0]), int64(args[1]), int(args[2]))
	return uint64(off)
}

func mmap(u models.Usercorn, args []uint64) uint64 {
	addr, _ := u.Mmap(args[0], args[1])
	return uint64(addr)
}

func munmap(u models.Usercorn, args []uint64) uint64 {
	return 0
}

var syscalls = map[string]Syscall{
	"exit": {exit, 1},
	// "fork": {fork, 0},
	"read":   {read, 3},
	"write":  {write, 3},
	"open":   {open, 3},
	"close":  {_close, 1},
	"lseek":  {lseek, 3},
	"mmap":   {mmap, 6},
	"munmap": {munmap, 2},
}

func Call(u models.Usercorn, name string, getArgs func(n int) []uint64) (uint64, error) {
	s, ok := syscalls[name]
	if !ok {
		return 0, fmt.Errorf("Unknown syscall: %s", s)
	}
	return s.Func(u, getArgs(s.Args)), nil
}
