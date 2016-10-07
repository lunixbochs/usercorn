package models

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type memDelta struct {
	addr  uint64
	last  []byte
	data  []byte
	write bool
	tag   byte
}

type MemLog struct {
	order  binary.ByteOrder
	log    []*memDelta
	frozen bool
}

func NewMemLog(order binary.ByteOrder) *MemLog {
	return &MemLog{order: order}
}

func (m *MemLog) Empty() bool {
	return len(m.log) == 0
}

func (m *MemLog) Reset() {
	m.log = nil
	m.frozen = false
}

func (m *MemLog) Freeze() {
	m.frozen = true
}

func (m *MemLog) Flush(bits int) string {
	tmp := m.String(bits)
	m.Reset()
	return tmp
}

func (m *MemLog) Adjacent(addr uint64, p []byte, write bool) (delta *memDelta, dup bool) {
	for _, delta := range m.log {
		if delta.write != write {
			continue
		}
		if addr == delta.addr && bytes.Equal(p, delta.last) {
			return delta, true
		}
		if addr == delta.addr+uint64(len(delta.data)) || addr == delta.addr-uint64(len(p)) {
			return delta, false
		}
	}
	return nil, false
}

func (m *MemLog) UpdateBytes(addr uint64, p []byte, write bool) {
	if m.frozen {
		return
	}
	var delta *memDelta
	var dup, before bool
	if delta, dup = m.Adjacent(addr, p, write); delta != nil {
		// adjacent to old memory delta
		if dup {
			return
		}
		if addr < delta.addr {
			delta.addr -= uint64(len(p))
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
		delta = &memDelta{addr, nil, nil, write, ' '}
		m.log = append(m.log, delta)
	}
	if before {
		data := make([]byte, len(p), len(p)+len(delta.data))
		copy(data, p)
		copy(data[len(p):], delta.data)
		delta.data = data
		delta.last = delta.data[:len(p)]
	} else {
		delta.data = append(delta.data, p...)
		delta.last = delta.data[len(delta.data)-len(p):]
	}
}

func (m *MemLog) Update(addr uint64, size int, value int64, write bool) {
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
	m.UpdateBytes(addr, tmp[:size], write)
}

func (m *MemLog) String(bits int) string {
	var out []string
	for _, d := range m.log {
		t := "R"
		if d.write {
			t = "W"
		}
		for i, line := range HexDump(d.addr, d.data, bits) {
			if i == 0 {
				out = append(out, fmt.Sprintf("%s%c %s %s%c\n", t, d.tag, line, t, d.tag))
			} else {
				out = append(out, fmt.Sprintf("   %s\n", line))
			}
		}
	}
	return strings.Join(out, "")
}
