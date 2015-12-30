package models

import (
	"fmt"
)

type Mmap struct {
	Addr, Size uint64
	File       *MappedFile
}

func (m *Mmap) String() string {
	desc := fmt.Sprintf("0x%x-0x%x", m.Addr, m.Addr+m.Size)
	if m.File != nil {
		desc += fmt.Sprintf(" (%s)", m.File.Name)
	}
	return desc
}
