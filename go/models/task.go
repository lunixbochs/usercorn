package models

import (
	"encoding/binary"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Task interface {
	cpu.Cpu
	// Cpu wrappers
	Mappings() []*Mmap
	MemMap(addr, size uint64) error
	MemReserve(addr, size uint64, force bool) (*Mmap, error)
	Mmap(addr, size uint64) (*Mmap, error)

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
