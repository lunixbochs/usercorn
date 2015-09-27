package models

import (
	"encoding/binary"
	"fmt"
	"os"
)

type memDelta struct {
	addr  uint64
	data  []byte
	write bool
}

type MemLog struct {
	order binary.ByteOrder
	log   []*memDelta
	read  *memDelta
	write *memDelta
}

func NewMemLog(order binary.ByteOrder) *MemLog {
	return &MemLog{order: order}
}

func (m *MemLog) Empty() bool {
	return len(m.log) == 0
}

func (m *MemLog) Reset() {
	m.log = nil
	m.read = nil
	m.write = nil
}

func (m *MemLog) Adjacent(addr uint64, write bool) bool {
	if m.Empty() {
		return false
	}
	if write {
		return !(m.write == nil) && addr == m.write.addr+uint64(len(m.write.data))
	} else {
		return !(m.read == nil) && addr == m.read.addr+uint64(len(m.read.data))
	}
}

func (m *MemLog) Update(addr uint64, size int, value int64, write bool) {
	if !m.Adjacent(addr, write) {
		delta := &memDelta{addr, nil, write}
		if write {
			m.write = delta
		} else {
			m.read = delta
		}
		m.log = append(m.log, delta)
	}
	var tmp [8]byte
	switch size {
	case 1:
		tmp[0] = byte(value)
	case 2:
		m.order.PutUint16(tmp[:], uint16(value))
	case 4:
		m.order.PutUint32(tmp[:], uint32(value))
	case 8:
		m.order.PutUint64(tmp[:], uint64(value))
	}
	if write {
		m.write.data = append(m.write.data, tmp[:size]...)
	} else {
		m.read.data = append(m.read.data, tmp[:size]...)
	}
}

func (m *MemLog) Print(indent string, bits int) {
	for _, d := range m.log {
		t := "R"
		if d.write {
			t = "W"
		}
		for i, line := range HexDump(d.addr, d.data, bits) {
			if i == 0 {
				fmt.Fprintf(os.Stderr, "%s%s %s\n", indent, t, line)
			} else {
				fmt.Fprintf(os.Stderr, "%s  %s\n", indent, line)
			}
		}
	}
}
