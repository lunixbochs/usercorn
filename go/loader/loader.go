package loader

import (
	"encoding/binary"
)

type LoaderHeader struct {
	arch      string
	bits      int
	byteOrder binary.ByteOrder
	os        string
	entry     uint64
}

func (l *LoaderHeader) Arch() string {
	return l.arch
}

func (l *LoaderHeader) Bits() int {
	return l.bits
}

func (l *LoaderHeader) ByteOrder() binary.ByteOrder {
	if l.byteOrder == nil {
		return binary.LittleEndian
	}
	return l.byteOrder
}

func (l *LoaderHeader) OS() string {
	return l.os
}

func (l *LoaderHeader) Entry() uint64 {
	return l.entry
}
