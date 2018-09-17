package cpu

import (
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

type MemSim struct {
	Mem Pages
}

// Checks whether the address range exists in the currently-mapped memory.
// If prot > 0, ensures that each region has the entire protection mask provided.
func (m *MemSim) RangeValid(addr, size uint64, prot int) (mapGood bool, protGood bool) {
	_, first := m.Mem.bsearch(addr)
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

// Maps <addr> - <addr>+<size> and protects with prot.
// If zero is false, it first copies any existing data in this range to the new mapping.
// Any overlapping regions will be unmapped, then then the mapping list will be sorted by address
// to allow binary search and simpler reads / bound checks.
func (m *MemSim) Map(addr, size uint64, prot int, zero bool) *Page {
	data := make([]byte, size)
	if !zero {
		m.Read(addr, data, 0)
	}
	if gmem, _ := m.RangeValid(addr, size, 0); gmem {
		m.Unmap(addr, size)
	}
	page := &Page{Addr: addr, Size: size, Prot: prot, Data: data}
	m.Mem = append(m.Mem, page)
	sort.Sort(m.Mem)
	return page
}

// this is *exactly* unmap, but the "middle" pages of each split are re-protected
func (m *MemSim) Prot(addr, size uint64, prot int) {
	// truncate entries overlapping addr, size
	tmp := make([]*Page, 0, len(m.Mem))
	pos := 0
	/*
		pos, _ := m.Mem.bsearch(addr)
		copy(tmp, m.Mem[:pos])
	*/
	for _, mm := range m.Mem[pos:] {
		if oaddr, osize, ok := mm.Intersect(addr, size); ok {
			left, right := mm.Split(oaddr, osize)
			if left != nil {
				tmp = append(tmp, left)
			}
			tmp = append(tmp, mm)
			mm.Prot = prot
			if right != nil {
				tmp = append(tmp, right)
			}
		} else {
			tmp = append(tmp, mm)
		}
	}
	m.Mem = tmp
}

func (m *MemSim) Unmap(addr, size uint64) {
	// truncate entries overlapping addr, size
	tmp := make([]*Page, 0, len(m.Mem))
	pos := 0
	/*
		pos, _ := m.Mem.bsearch(addr)
		copy(tmp, m.Mem[:pos])
	*/
	for _, mm := range m.Mem[pos:] {
		if oaddr, osize, ok := mm.Intersect(addr, size); ok {
			left, right := mm.Split(oaddr, osize)
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
	_, i := m.Mem.bsearch(addr)
	if i >= 0 {
		for _, mm := range m.Mem[i:] {
			if !mm.Contains(addr) {
				break
			}
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
	_, i := m.Mem.bsearch(addr)
	if i >= 0 {
		for _, mm := range m.Mem[i:] {
			if !mm.Contains(addr) {
				break
			}
			o := addr - mm.Addr
			n := copy(mm.Data[o:], p)
			addr, p = addr+uint64(n), p[n:]
		}
	}
	return nil
}
