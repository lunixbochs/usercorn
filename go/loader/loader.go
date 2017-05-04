package loader

import (
	"debug/dwarf"
	"encoding/binary"

	"github.com/lunixbochs/usercorn/go/models"
)

type LoaderBase struct {
	arch      string
	bits      int
	byteOrder binary.ByteOrder
	os        string
	entry     uint64
	symCache  []models.Symbol
}

func (l *LoaderBase) Arch() string {
	return l.arch
}

func (l *LoaderBase) Bits() int {
	return l.bits
}

func (l *LoaderBase) ByteOrder() binary.ByteOrder {
	if l.byteOrder == nil {
		return binary.LittleEndian
	}
	return l.byteOrder
}

func (l *LoaderBase) OS() string {
	return l.os
}

func (l *LoaderBase) Entry() uint64 {
	return l.entry
}

// Everything below this line is a stub, intended to be reimplemented by the struct embedding LoaderBase.
// These methods are defined to allow implementing a partial loader.

func (l *LoaderBase) DWARF() (*dwarf.Data, error) {
	return nil, nil
}

func (l *LoaderBase) DataSegment() (uint64, uint64) {
	return 0, 0
}

func (l *LoaderBase) Header() (uint64, []byte, int) {
	return 0, nil, 0
}

func (l *LoaderBase) Interp() string {
	return ""
}

func (l *LoaderBase) Segments() ([]models.SegmentData, error) {
	return nil, nil
}

func (l *LoaderBase) Symbols() ([]models.Symbol, error) {
	return nil, nil
}

func (l *LoaderBase) Type() int {
	return EXEC
}
