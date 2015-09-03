package models

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
)

// TODO upstream Unicorn interface into bindings
type Unicorn interface {
	MemMap(addr, size uint64) error
	MemMapProt(addr, size uint64, prot int) error
	MemRead(addr, size uint64) ([]byte, error)
	MemReadInto(dst []byte, addr uint64) error
	MemReadStr(addr uint64) (string, error)
	MemWrite(addr uint64, data []byte) error
	RegRead(reg int) (uint64, error)
	RegWrite(reg int, value uint64) error
	Start(begin, until uint64) error
	StartWithOptions(begin, until uint64, options *uc.UcOptions) error
	Stop() error
}

type Usercorn interface {
	Unicorn
	Arch() *Arch
	Bits() uint
	Disas(addr, size uint64) (string, error)
	Brk(addr uint64) (uint64, error)
	Mmap(addr, size uint64) (uint64, error)
	MemReader(addr uint64) io.Reader
	MemWriter(addr uint64) io.Writer
	PackAddr(buf []byte, n uint64) error
	UnpackAddr(buf []byte) uint64
	Pop() (uint64, error)
	Push(n uint64) error
	ReadRegs(reg []int) ([]uint64, error)
	Syscall(table map[int]string, num int, getArgs func(n int) ([]uint64, error)) (uint64, error)
}
