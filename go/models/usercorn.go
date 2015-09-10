package models

import (
	"encoding/binary"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
)

type Usercorn interface {
	uc.Unicorn
	Arch() *Arch
	Bits() uint
	ByteOrder() binary.ByteOrder
	Disas(addr, size uint64) (string, error)
	PrefixPath(s string, force bool) string
	Brk(addr uint64) (uint64, error)
	Mmap(addr, size uint64) (uint64, error)
	MemReadStr(addr uint64) (string, error)
	MemReader(addr uint64) io.Reader
	MemWriter(addr uint64) io.Writer
	PackAddr(buf []byte, n uint64) error
	UnpackAddr(buf []byte) uint64
	Pop() (uint64, error)
	Push(n uint64) error
	ReadRegs(reg []int) ([]uint64, error)
	RegDump() ([]RegVal, error)
	PosixInit(args, env []string) error
	Syscall(num int, name string, getArgs func(n int) ([]uint64, error)) (uint64, error)
}
