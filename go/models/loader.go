package models

import (
	"debug/dwarf"
	"encoding/binary"
)

type Symbol struct {
	Name       string
	Start, End uint64
	Dynamic    bool
}

type Loader interface {
	Arch() string
	Bits() int
	ByteOrder() binary.ByteOrder
	OS() string
	Entry() uint64
	Type() int
	Interp() string
	Header() (uint64, []byte, int)
	Symbols() ([]Symbol, error)
	Segments() ([]SegmentData, error)
	DataSegment() (uint64, uint64)
	DWARF() (*dwarf.Data, error)
}
