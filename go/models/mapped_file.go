package models

import (
	"debug/dwarf"
	"fmt"
	"path"
)

type MappedFile struct {
	Name       string
	Off        int64
	Addr, Size uint64
	Symbols    []Symbol
	DWARF      *dwarf.Data
}

func (m *MappedFile) Contains(addr uint64) bool {
	return m.Addr <= addr && m.Addr+m.Size > addr
}

func (m *MappedFile) Symbolicate(addr uint64) (result Symbol, distance uint64) {
	if !m.Contains(addr) || len(m.Symbols) == 0 {
		return
	}
	addr -= m.Addr
	var nearest Symbol
	var min int64 = -1
	for _, sym := range m.Symbols {
		if sym.Start == 0 {
			continue
		}
		if sym.Contains(addr) {
			dist := int64(addr - sym.Start)
			if dist < min || min == -1 {
				nearest = sym
				min = dist
			}
		}
	}
	if min >= 0 {
		return nearest, uint64(min)
	}
	return
}

// TODO: Use a map for O(n) -> O(1)
// TODO: Do I want this to just return addr?
// Part of problem is adjusting for memory offset,
// and it's gross if the caller needs to do that manually.
func (m *MappedFile) SymbolLookup(name string) Symbol {
	for _, sym := range m.Symbols {
		if sym.Name == name {
			var s Symbol = sym
			s.Start += m.Addr - uint64(m.Off)
			return s
		}
	}
	return Symbol{}
}

func (m *MappedFile) FileLine(addr uint64) string {
	getAddr := func(f *dwarf.Field) uint64 {
		if f == nil {
			return 0
		}
		switch f.Class {
		case dwarf.ClassAddress:
			return f.Val.(uint64)
		case dwarf.ClassConstant:
			return uint64(f.Val.(int64))
		}
		return 0
	}
	if !m.Contains(addr) || m.DWARF == nil {
		return ""
	}
	addr -= m.Addr
	reader := m.DWARF.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}
		if entry.Tag == dwarf.TagCompileUnit {
			lowpc, highpc := getAddr(entry.AttrField(dwarf.AttrLowpc)), getAddr(entry.AttrField(dwarf.AttrHighpc))
			if lowpc <= addr && lowpc+highpc > addr {
				if reader, err := m.DWARF.LineReader(entry); err == nil {
					var line dwarf.LineEntry
					if err := reader.SeekPC(addr, &line); err == nil {
						return fmt.Sprintf("%s:%d", path.Base(line.File.Name), line.Line)
					}
				}
			}
		}
		reader.SkipChildren()
	}
	return ""
}
