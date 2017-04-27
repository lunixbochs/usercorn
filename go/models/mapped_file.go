package models

type MappedFile struct {
	Name       string
	Off        int64
	Addr, Size uint64

	DebugFile *DebugFile
}

func (m *MappedFile) Contains(addr uint64) bool {
	return m.Addr <= addr && m.Addr+m.Size > addr
}

func (m *MappedFile) Symbolicate(addr uint64) (result Symbol, distance uint64) {
	return m.DebugFile.Symbolicate(addr - m.Addr + uint64(m.Off))
}

func (m *MappedFile) SymbolLookup(name string) Symbol {
	sym := m.DebugFile.SymbolLookup(name)
	sym.Start += m.Addr - uint64(m.Off)
	return sym
}

func (m *MappedFile) FileLine(addr uint64) *SourceLine {
	return m.DebugFile.FileLine(addr - m.Addr + uint64(m.Off))
}
