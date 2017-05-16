package cpu

import (
	"github.com/pkg/errors"
)

// wraps MemSim to make a Cpu interface-compatible memory model
type Mem struct {
	// methods return an error for addresses that do not fit inside mask
	// calculated by NewMem using ^uint64(0) >> (64 - bits)
	mask uint64
	// hooks is set when passing *Mem to NewHooks()
	hooks *Hooks
	*MemSim
}

func NewMem(bits uint) *Mem {
	return &Mem{mask: ^uint64(0) >> (64 - bits)}
}

func (m *Mem) MemMapProt(addr, size uint64, prot int) error {
	if addr+size&m.mask != addr+size {
		return errors.New("region outside memory range")
	}
	m.MemSim.Map(addr, size, prot, false)
	return nil
}

func (m *Mem) MemProt(addr, size uint64, prot int) error {
	if mapped, _ := m.RangeValid(addr, size, 0); !mapped {
		return errors.New("range not mapped")
	}
	m.MemSim.Prot(addr, size, prot)
	return nil
}

func (m *Mem) MemUnmap(addr, size uint64) error {
	if mapped, _ := m.RangeValid(addr, size, 0); !mapped {
		return errors.New("range not mapped")
	}
	m.MemSim.Unmap(addr, size)
	return nil
}

func (m *Mem) MemReadInto(addr uint64, p []byte) error {
	return m.MemSim.Read(addr, p, PROT_READ)
}

func (m *Mem) MemRead(addr, size uint64) ([]byte, error) {
	p := make([]byte, size)
	if err := m.MemReadInto(addr, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (m *Mem) MemWrite(addr uint64, p []byte) error {
	return m.MemSim.Write(addr, p, PROT_WRITE)
}
