package cpu

import (
	"bytes"
	"fmt"
	"sort"
)

type MemError struct {
	Addr uint64
	Size int
	Enum int
}

func (m *MemError) Error() string {
	reason := "memory error"
	switch m.Enum {
	case MEM_WRITE_UNMAPPED:
		reason = "unmapped write"
	case MEM_READ_UNMAPPED:
		reason = "unmapped read"
	case MEM_FETCH_UNMAPPED:
		reason = "unmapped fetch"
	case MEM_WRITE_PROT:
		reason = "protected write"
	case MEM_READ_PROT:
		reason = "protected read"
	case MEM_FETCH_PROT:
		reason = "protected exec"
	}
	return fmt.Sprintf("%s at %#x(%d)", reason, m.Addr, m.Size)
}

type MemRegion struct {
	Addr uint64
	Size uint64
	Prot int
	Data []byte
}

func (m *MemRegion) String() string {
	// duplicated from go/models/mmap.go
	desc := fmt.Sprintf("0x%x-0x%x", m.Addr, m.Addr+m.Size)
	// add prot
	prots := []int{PROT_READ, PROT_WRITE, PROT_EXEC}
	chars := []string{"r", "w", "x"}
	prot := " "
	for i := range prots {
		if m.Prot&prots[i] != 0 {
			prot += chars[i]
		} else {
			prot += "-"
		}
	}
	desc += prot
	return desc
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
		extra := bytes.Repeat([]byte{0}, int(nraddr-raddr))
		m.Data = append(m.Data, extra...)
	}
	m.Addr, m.Size = addr, size
	return left, right
}

func (m *MemRegion) Write(addr uint64, p []byte) {
	copy(m.Data[addr-m.Addr:], p)
}

type memSort []*MemRegion

func (m memSort) Len() int           { return len(m) }
func (m memSort) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m memSort) Less(i, j int) bool { return m[i].Addr < m[j].Addr }

type MemSim struct {
	Mem []*MemRegion
}

func (m *MemSim) Find(addr uint64) *MemRegion {
	for _, mm := range m.Mem {
		if mm.Contains(addr) {
			return mm
		}
	}
	return nil
}

// Checks whether the address range exists in the currently-mapped memory.
// If prot > 0, ensures that each region has the entire protection mask provided.
func (m *MemSim) RangeValid(addr, size uint64, prot int) (mapGood bool, protGood bool) {
	first := m.bsearch(addr)
	if first == -1 {
		return false, false
	}
	protGood = true
	end := addr + size
	for _, mm := range m.Mem[first:] {
		if mm.Contains(addr) {
			if prot > 0 && (mm.Prot == 0 || mm.Prot&prot != prot) {
				protGood = false
			}
			addr = mm.Addr + mm.Size
			if addr >= end {
				break
			}
		} else {
			break
		}
	}
	return addr >= end, protGood
}

// binary search to find index of first region containing addr, if any, else -1
func (m *MemSim) bsearch(addr uint64) int {
	l := 0
	r := len(m.Mem) - 1
	for l <= r {
		mid := (l + r) / 2
		e := m.Mem[mid]
		if addr >= e.Addr {
			if addr < e.Addr+e.Size {
				return mid
			}
			l = mid + 1
		} else if addr < e.Addr {
			r = mid - 1
		}
	}
	return -1
}

// Maps <addr> - <addr>+<size> and protects with prot.
// If zero is false, it first copies any existing data in this range to the new mapping.
// Any overlapping regions will be unmapped, then then the mapping list will be sorted by address
// to allow binary search and simpler reads / bound checks.
func (m *MemSim) Map(addr, size uint64, prot int, zero bool) {
	data := make([]byte, size)
	if !zero {
		m.Read(addr, data, 0)
	}
	if gmem, _ := m.RangeValid(addr, size, 0); gmem {
		m.Unmap(addr, size)
	}
	m.Mem = append(m.Mem, &MemRegion{Addr: addr, Size: size, Prot: prot, Data: data})
	sort.Sort(memSort(m.Mem))
}

func (m *MemSim) Prot(addr, size uint64, prot int) {
	m.Map(addr, size, prot, false)
}

func (m *MemSim) Unmap(addr, size uint64) {
	// truncate entries overlapping addr, size
	tmp := make([]*MemRegion, 0, len(m.Mem))
	// TODO: use a binary search to find the leftmost mapping?
	for _, mm := range m.Mem {
		if mm.Overlaps(addr, size) {
			left, right := mm.Split(addr, size)
			if left != nil {
				tmp = append(tmp, left)
			}
			if right != nil {
				tmp = append(tmp, right)
			}
		} else {
			tmp = append(tmp, mm)
		}
	}
	m.Mem = tmp
}

// TODO: allow partial reads, and return amount read?
// alternatively, return the offset that failed so they can retry
func (m *MemSim) Read(addr uint64, p []byte, prot int) error {
	if gmap, gprot := m.RangeValid(addr, uint64(len(p)), prot); !gmap {
		if prot&PROT_EXEC == PROT_EXEC {
			return &MemError{Addr: addr, Size: len(p), Enum: MEM_FETCH_UNMAPPED}
		}
		return &MemError{Addr: addr, Size: len(p), Enum: MEM_READ_UNMAPPED}
	} else if !gprot {
		if prot&PROT_EXEC == PROT_EXEC {
			return &MemError{Addr: addr, Size: len(p), Enum: MEM_FETCH_PROT}
		}
		return &MemError{Addr: addr, Size: len(p), Enum: MEM_READ_PROT}
	}
	// TODO: consecutive read using bsearch
	for _, mm := range m.Mem {
		if mm.Contains(addr) {
			o := addr - mm.Addr
			n := copy(p, mm.Data[o:])
			addr, p = addr+uint64(n), p[n:]
		}
	}
	return nil
}

// TODO: allow partial writes on error, and return amount read?
// alternatively, return the offset that failed so they can retry
func (m *MemSim) Write(addr uint64, p []byte, prot int) error {
	if gmap, gprot := m.RangeValid(addr, uint64(len(p)), prot); !gmap {
		return &MemError{Addr: addr, Size: len(p), Enum: MEM_WRITE_UNMAPPED}
	} else if !gprot {
		return &MemError{Addr: addr, Size: len(p), Enum: MEM_WRITE_PROT}
	}
	// TODO: consecutive write using bsearch
	for _, mm := range m.Mem {
		if mm.Contains(addr) {
			o := addr - mm.Addr
			n := copy(mm.Data[o:], p)
			addr, p = addr+uint64(n), p[n:]
		}
	}
	return nil
}
