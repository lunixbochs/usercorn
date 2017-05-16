package cpu

import (
	"bytes"
	"github.com/pkg/errors"
)

type MemRegion struct {
	Addr uint64
	Size uint64
	Prot int
	Data []byte
}

func (m *MemRegion) Contains(addr uint64) bool {
	return addr >= m.Addr && addr < m.Addr+m.Size
}

func (m *MemRegion) Overlaps(addr, size uint64) bool {
	e1, e2 := m.Addr+m.Size, addr+size
	return (m.Addr >= addr && m.Addr < e2) || (addr >= m.Addr && addr < e1)
}

func (m *MemRegion) Split(addr, size uint64) (left, right *MemRegion) {
	// space on the right
	if addr+size < m.Addr+m.Size {
		ra := addr + size
		rs := m.Addr + m.Size - ra
		o := ra - m.Addr
		right = &MemRegion{Addr: ra, Size: rs, Data: m.Data[o : o+rs]}
		m.Data = m.Data[:o]
	}
	// space on the left
	if addr > m.Addr {
		ls := addr - m.Addr
		left = &MemRegion{Addr: m.Addr, Size: ls, Data: m.Data[:ls]}
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

func (m *MemRegion) Write(addr uint64, p []byte) {
	copy(m.Data[addr-m.Addr:], p)
}

type MemSim struct {
	mem []*MemRegion
}

func (m *MemSim) Find(addr uint64) *MemRegion {
	for _, mm := range m.mem {
		if mm.Contains(addr) {
			return mm
		}
	}
	return nil
}

// returns whether the address range exists in the currently-mapped memory
// FIXME: algorithm is terrible
func (m *MemSim) RangeValid(addr, size uint64) bool {
	end := addr + size
outer:
	for addr < end {
		for _, mm := range m.mem {
			if mm.Contains(addr) {
				addr = mm.Addr + mm.Size
			}
			continue outer
		}
		return false
	}
	return true
}

func (m *MemSim) Map(addr, size uint64, prot int, zero bool) {
	data := make([]byte, size)
	if !zero {
		m.Read(addr, data, 0)
	}
	m.Unmap(addr, size)
	m.mem = append(m.mem, &MemRegion{Addr: addr, Size: size, Prot: prot, Data: data})
}

func (m *MemSim) Prot(addr, size uint64, prot int) {
	m.Map(addr, size, prot, false)
}

func (m *MemSim) Unmap(addr, size uint64) {
	// truncate entries overlapping addr, size
	var tmp, pop []*MemRegion
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

// TODO: check that read or write covered entire range
func (m *MemSim) Read(addr uint64, p []byte, prot int) error {
	for _, mm := range m.mem {
		if mm.Contains(addr) {
			// enforce PROT_READ or PROT_EXEC
			if prot != 0 && mm.Prot&prot != prot {
				return errors.New("read fault")
			}
			o := addr - mm.Addr
			copy(p, mm.Data[o:])
		}
	}
	return nil
}

func (m *MemSim) Write(addr uint64, p []byte, prot int) error {
	for _, mm := range m.mem {
		if mm.Contains(addr) {
			if prot != 0 && mm.Prot&prot != prot {
				return errors.New("write fault")
			}
			o := addr - mm.Addr
			copy(mm.Data[o:], p)
		}
	}
	return nil
}
