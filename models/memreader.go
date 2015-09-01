package models

type MemReader struct {
	U    Unicorn
	Addr uint64
}

func (m *MemReader) Read(p []byte) (int, error) {
	err := m.U.MemReadInto(p, m.Addr)
	if err != nil {
		return 0, err
	}
	m.Addr += uint64(len(p))
	return len(p), nil
}
