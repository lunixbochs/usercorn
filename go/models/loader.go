package models

import (
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
	Header() ([]byte, int)
	Symbols() ([]Symbol, error)
	Segments() ([]SegmentData, error)
	DataSegment() (uint64, uint64)
}
