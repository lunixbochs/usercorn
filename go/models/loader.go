package models

import (
	"encoding/binary"
)

type Loader interface {
	Arch() string
	Bits() int
	ByteOrder() binary.ByteOrder
	OS() string
	Entry() uint64
	Type() int
	Interp() string
	Header() ([]byte, int)
	Symbolicate(addr uint64) (string, error)
	Segments() ([]SegmentData, error)
	DataSegment() (uint64, uint64)
}
