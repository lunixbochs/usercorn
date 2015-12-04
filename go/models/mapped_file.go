package models

type MappedFile struct {
	Name       string
	Off        int64
	Addr, Size uint64
	Symbols    []Symbol
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
