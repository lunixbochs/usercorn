package models

import (
	"bytes"
)

type Mem struct {
	Addr uint64
	Size uint64
	Prot int
	Data []byte
}

func (m *Mem) Contains(addr uint64) bool {
	return addr >= m.Addr && addr < m.Addr+m.Size
}

func (m *Mem) Overlaps(addr, size uint64) bool {
	e1, e2 := m.Addr+m.Size, addr+size
	return (m.Addr >= addr && m.Addr < e2) || (addr >= m.Addr && addr < e1)
}

func (m *Mem) Split(addr, size uint64) (left, right *Mem) {
	// space on the right
	if addr+size < m.Addr+m.Size {
		ra := addr + size
		rs := m.Addr + m.Size - ra
		o := ra - m.Addr
		right = &Mem{Addr: ra, Size: rs, Data: m.Data[o : o+rs]}
		m.Data = m.Data[:o]
	}
	// space on the left
	if addr > m.Addr {
		ls := addr - m.Addr
		left = &Mem{Addr: m.Addr, Size: ls, Data: m.Data[:ls]}
		m.Data = m.Data[ls:]
	}
	// pad the middle
	if addr < m.Addr {
		extra := bytes.Repeat([]byte{0}, int(m.Addr-addr))
		m.Data = append(extra, m.Data...)
	}
	raddr, nraddr := m.Addr+m.Size, addr+size
	if nraddr > raddr {
		extra := bytes.Repeat([]byte{0}, int(raddr-nraddr))
		m.Data = append(m.Data, extra...)
	}
	m.Addr, m.Size = addr, size
	return left, right
}

func (m *Mem) Write(addr uint64, p []byte) {
	copy(m.Data[addr-m.Addr:], p)
}

type MemSim struct {
	mem []*Mem
}

func (m *MemSim) Find(addr uint64) *Mem {
	for _, mm := range m.mem {
		if mm.Contains(addr) {
			return mm
		}
	}
	return nil
}

func (m *MemSim) Map(addr, size uint64, prot int, zero bool) {
	data := make([]byte, size)
	if !zero {
		m.Read(addr, data)
	}
	m.Unmap(addr, size)
	m.mem = append(m.mem, &Mem{Addr: addr, Size: size, Prot: prot, Data: data})
}

func (m *MemSim) Unmap(addr, size uint64) {
	// truncate entries overlapping addr, size
	var tmp, pop []*Mem
	for _, mm := range m.mem {
		if mm.Overlaps(addr, size) {
			pop = append(pop, mm)
			left, right := mm.Split(addr, size)
			if left != nil {
				tmp = append(tmp, left)
			}
			if right != nil {
				tmp = append(tmp, right)
			}
		}
	}
	// remove entries in `pop` from m.mem
outer:
	for _, mm := range m.mem {
		for _, p := range pop {
			if mm == p {
				continue outer
			}
		}
		tmp = append(tmp, mm)
	}
	m.mem = tmp
}

func (m *MemSim) Read(addr uint64, p []byte) {
	for _, mm := range m.mem {
		if mm.Contains(addr) {
			o := addr - mm.Addr
			copy(p, mm.Data[o:])
		}
	}
}

func (m *MemSim) Write(addr uint64, p []byte) {
	for _, mm := range m.mem {
		if mm.Contains(addr) {
			o := addr - mm.Addr
			copy(mm.Data[o:], p)
		}
	}
}
