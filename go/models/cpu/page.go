package cpu

import (
	"bytes"
	"fmt"
)

type Page struct {
	Addr uint64
	Size uint64
	Prot int
	Data []byte

	Desc string
	File *FileDesc
}

func (m *Page) String() string {
	// add prot
	prots := []int{PROT_READ, PROT_WRITE, PROT_EXEC}
	chars := []string{"r", "w", "x"}
	prot := ""
	for i := range prots {
		if m.Prot&prots[i] != 0 {
			prot += chars[i]
		} else {
			prot += "-"
		}
	}
	desc := fmt.Sprintf("0x%x-0x%x %s", m.Addr, m.Addr+m.Size, prot)
	// append mmap'd file and desc
	if m.File != nil {
		desc += fmt.Sprintf(" %s", m.File.Name)
	}
	if m.Desc != "" {
		desc += fmt.Sprintf(" [%s]", m.Desc)
	}
	return desc
}

func (m *Page) Contains(addr uint64) bool {
	return addr >= m.Addr && addr < m.Addr+m.Size
}

func (m *Page) Overlaps(addr, size uint64) bool {
	e1, e2 := m.Addr+m.Size, addr+size
	return (m.Addr >= addr && m.Addr < e2) || (addr >= m.Addr && addr < e1)
}

func (m *Page) Split(addr, size uint64) (left, right *Page) {
	// space on the right
	if addr+size < m.Addr+m.Size {
		ra := addr + size
		rs := m.Addr + m.Size - ra
		o := ra - m.Addr
		right = &Page{Addr: ra, Size: rs, Data: m.Data[o : o+rs]}
		m.Data = m.Data[:o]
	}
	// space on the left
	if addr > m.Addr {
		ls := addr - m.Addr
		left = &Page{Addr: m.Addr, Size: ls, Data: m.Data[:ls]}
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

func (m *Page) Write(addr uint64, p []byte) {
	copy(m.Data[addr-m.Addr:], p)
}

type PageSort []*Page

func (m PageSort) Len() int           { return len(m) }
func (m PageSort) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m PageSort) Less(i, j int) bool { return m[i].Addr < m[j].Addr }
