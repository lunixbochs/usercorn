package models

import (
	"encoding/binary"
	"fmt"
	"os"
)

type memDelta struct {
	addr  uint64
	value int64
	data  []byte
	write bool
	tag   byte
}

type MemLog struct {
	order binary.ByteOrder
	log   []*memDelta
}

func NewMemLog(order binary.ByteOrder) *MemLog {
	return &MemLog{order: order}
}

func (m *MemLog) Empty() bool {
	return len(m.log) == 0
}

func (m *MemLog) Reset() {
	m.log = nil
}

func (m *MemLog) Adjacent(addr uint64, value int64, size int, write bool) (delta *memDelta, dup bool) {
	for _, delta := range m.log {
		if delta.write != write {
			continue
		}
		if addr == delta.addr && value == delta.value {
			return delta, true
		}
		if addr == delta.addr+uint64(len(delta.data)) || addr == delta.addr-uint64(size) {
			return delta, false
		}
	}
	return nil, false
}

func (m *MemLog) Update(addr uint64, size int, value int64, write bool) {
	var delta *memDelta
	var dup, before bool
	if delta, dup = m.Adjacent(addr, value, size, write); delta != nil {
		// adjacent to old memory delta
		if dup {
			return
		}
		if addr < delta.addr {
			delta.addr -= uint64(size)
			before = true
		}
		var tag byte
		if before {
			tag = '<'
		} else {
			tag = '>'
		}
		if delta.tag == ' ' {
			delta.tag = tag
		} else if delta.tag != tag {
			delta.tag = '~'
		}
	} else {
		// entirely new memory delta
		delta = &memDelta{addr, value, nil, write, ' '}
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
	if before {
		data := make([]byte, size, size+len(delta.data))
		copy(data, tmp[:size])
		delta.data = append(data, delta.data...)
	} else {
		delta.data = append(delta.data, tmp[:size]...)
	}
	delta.value = value
}

func (m *MemLog) Print(indent string, bits int) {
	for _, d := range m.log {
		t := "R"
		if d.write {
			t = "W"
		}
		for i, line := range HexDump(d.addr, d.data, bits) {
			if i == 0 {
				fmt.Fprintf(os.Stderr, "%s%s%c%s %s%c\n", indent, t, d.tag, line, t, d.tag)
			} else {
				fmt.Fprintf(os.Stderr, "%s  %s\n", indent, line)
			}
		}
	}
}
