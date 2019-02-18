package cpu

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
)

// wraps MemSim to make a Cpu interface-compatible memory model
type Mem struct {
	bits uint
	// methods return an error for addresses that do not fit inside mask
	// calculated by NewMem using ^uint64(0) >> (64 - bits)
	mask uint64
	// Mem.hooks is set when passing *Mem to NewHooks()
	hooks *Hooks
	// MemSim isn't exposed in the interface, so any cpu-facing functionality should be wrapped by Mem
	Sim *MemSim

	order binary.ByteOrder
}

func NewMem(bits uint, order binary.ByteOrder) *Mem {
	return &Mem{
		bits:  bits,
		mask:  ^uint64(0) >> (64 - bits),
		Sim:   &MemSim{},
		order: order,
	}
}

func (m *Mem) Maps() Pages {
	return m.Sim.Mem
}

func (m *Mem) MemMap(addr, size uint64, prot int) error {
	if addr+size&m.mask != addr+size {
		return errors.New("region outside memory range")
	}
	m.Sim.Map(addr, size, prot, true)
	return nil
}

func (m *Mem) MemProt(addr, size uint64, prot int) error {
	if mapped, _ := m.Sim.RangeValid(addr, size, 0); !mapped {
		return errors.New("range not mapped")
	}
	m.Sim.Prot(addr, size, prot)
	return nil
}

func (m *Mem) MemUnmap(addr, size uint64) error {
	if mapped, _ := m.Sim.RangeValid(addr, size, 0); !mapped {
		return errors.New("range not mapped")
	}
	m.Sim.Unmap(addr, size)
	return nil
}

func (m *Mem) MemZero(addr, size uint64) error {
	b := bytes.Repeat([]byte{0}, int(size))
	return m.MemWrite(addr, b)
}

func (m *Mem) MemReadInto(p []byte, addr uint64) error {
	return m.Sim.Read(addr, p, 0)
}

func (m *Mem) MemRead(addr, size uint64) ([]byte, error) {
	p := make([]byte, size)
	if err := m.MemReadInto(p, addr); err != nil {
		return nil, err
	}
	return p, nil
}

func (m *Mem) MemWrite(addr uint64, p []byte) error {
	return m.Sim.Write(addr, p, 0)
}

// ReadProt reads while checking protections. This exists to support a CPU interpreter.
func (m *Mem) ReadProt(addr, size uint64, prot int) ([]byte, error) {
	p := make([]byte, size)
	if err := m.Sim.Read(addr, p, prot); err != nil {
		if merr, ok := err.(*MemError); ok && m.hooks != nil {
			m.hooks.OnFault(merr.Enum, addr, int(size), 0)
		}
		return nil, err
	} else if m.hooks != nil {
		if prot&PROT_EXEC == PROT_EXEC {
			m.hooks.OnMem(MEM_FETCH, addr, int(size), 0)
		} else {
			m.hooks.OnMem(MEM_READ, addr, int(size), 0)
		}
	}
	return p, nil
}

// WriteProt writes while checking protections. This exists to support a CPU interpreter.
// Write hooks trigger in WriteUint for now.
func (m *Mem) WriteProt(addr uint64, p []byte, prot int) error {
	return m.Sim.Write(addr, p, prot)
}

func (m *Mem) ReadUint(addr uint64, size, prot int) (uint64, error) {
	if size > 8 {
		return 0, errors.Errorf("MemReadUint size too large: %d > 8", size)
	}
	p, err := m.ReadProt(addr, uint64(size), prot)
	if err != nil {
		return 0, err
	}
	return UnpackUint(m.order, size, p)
}

// WriteUint writes hook only triggers here, as we can't fill value in WriteProt
func (m *Mem) WriteUint(addr uint64, size, prot int, val uint64) error {
	var buf [8]byte
	if size > 8 {
		return errors.Errorf("MemWriteUint size too large: %d > 8", size)
	}
	if _, err := PackUint(m.order, size, buf[:], val); err != nil {
		return err
	}
	err := m.WriteProt(addr, buf[:size], prot)
	if err != nil {
		if merr, ok := err.(*MemError); ok && m.hooks != nil {
			m.hooks.OnFault(merr.Enum, addr, int(size), int64(val))
		}
	} else if m.hooks != nil {
		m.hooks.OnMem(MEM_WRITE, addr, int(size), int64(val))
	}
	return err
}
