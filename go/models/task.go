package models

import (
	"encoding/binary"
	"io"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type FileDesc struct {
	io.ReaderAt
	Name string
	Off  uint64
}

type Task interface {
	cpu.Cpu

	// Cpu wrappers
	Mappings() []*Mmap
	// deprecated: only used by RunAsm
	MemReserve(addr, size uint64, force bool) (*Mmap, error)
	Mmap(addr, size uint64, prot int, fixed bool, desc string, file *FileDesc) (uint64, error)
	Malloc(size uint64) (uint64, error)

	PackAddr(buf []byte, n uint64) ([]byte, error)
	UnpackAddr(buf []byte) uint64
	PopBytes(p []byte) error
	PushBytes(p []byte) (uint64, error)
	Pop() (uint64, error)
	Push(n uint64) (uint64, error)
	RegDump() ([]RegVal, error)

	// Helpers
	Arch() *Arch
	OS() string
	Bits() uint
	ByteOrder() binary.ByteOrder
	Asm(asm string, addr uint64) ([]byte, error)
	Dis(addr, size uint64, showBytes bool) (string, error)
}
