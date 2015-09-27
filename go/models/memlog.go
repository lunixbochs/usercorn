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
	tag   byte
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

func (m *MemLog) Adjacent(addr uint64, size int, write bool) bool {
	if m.Empty() {
		return false
	}
	if write && m.write == nil || !write && m.read == nil {
		return false
	}
	if write {
		return addr == m.write.addr+uint64(len(m.write.data)) || addr == m.write.addr-uint64(size)
	} else {
		return addr == m.read.addr+uint64(len(m.read.data)) || addr == m.read.addr-uint64(size)
	}
}

func (m *MemLog) Update(addr uint64, size int, value int64, write bool) {
	var delta *memDelta
	before := false
	if !m.Adjacent(addr, size, write) {
		delta = &memDelta{addr, nil, write, ' '}
		if write {
			m.write = delta
		} else {
			m.read = delta
		}
		m.log = append(m.log, delta)
	} else {
		if write {
			delta = m.write
		} else {
			delta = m.read
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
