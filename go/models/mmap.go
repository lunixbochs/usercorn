package models

import (
	"fmt"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type Mmap struct {
	Addr, Size uint64
	Prot       int
	File       *MappedFile
	Desc       string
}

func (m *Mmap) String() string {
	desc := fmt.Sprintf("0x%x-0x%x", m.Addr, m.Addr+m.Size)

	// add prot
	prots := []int{uc.PROT_READ, uc.PROT_WRITE, uc.PROT_EXEC}
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

	// append mmap'd file and desc
	if m.File != nil {
		desc += fmt.Sprintf(" %s", m.File.Name)
	}
	if m.Desc != "" {
		desc += fmt.Sprintf(" [%s]", m.Desc)
	}
	return desc
}
