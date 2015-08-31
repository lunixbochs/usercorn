package main

import (
	"encoding/binary"
	"errors"
	uc "github.com/lunixbochs/unicorn"

	"./models"
)

type Unicorn struct {
	*uc.Uc
	Arch   *models.Arch
	Bits   int
	Bsz    int
	memory []mmap
}

func NewUnicorn(a *models.Arch) (*Unicorn, error) {
	Uc, err := uc.NewUc(a.UC_ARCH, a.UC_MODE)
	if err != nil {
		return nil, err
	}
	return &Unicorn{
		Uc:   Uc,
		Arch: a,
		Bits: a.Bits,
		Bsz:  a.Bits / 8,
	}, nil
}

func (u *Unicorn) mapping(addr, size uint64) *mmap {
	for _, m := range u.memory {
		if addr < m.Start && addr+size > m.Start {
			return &m
		}
		if addr >= m.Start && addr < m.Start+m.Size {
			return &m
		}
	}
	return nil
}

func (u *Unicorn) MemMap(addr, size uint64) error {
	m := u.mapping(addr, size)
	for m != nil {
		a, b := m.Start, m.Start+m.Size
		if addr < a {
			size = a - addr
		} else if addr < b && addr+size > b {
			right := addr + size
			addr = b
			size = right - addr
		} else {
			return nil
		}
		m = u.mapping(addr, size)
	}
	u.memory = append(u.memory, mmap{addr, size})
	addr, size = align(addr, size, true)
	return u.Uc.MemMap(addr, size)
}

func (u *Unicorn) Mmap(addr, size uint64) (uint64, error) {
	if addr == 0 {
		addr = BASE
	}
	_, size = align(0, size, true)
	addr, size = align(addr, size)
	for i := addr; i < 1<<uint(u.Bits); i += UC_MEM_ALIGN {
		if u.mapping(addr, size) == nil {
			err := u.MemMap(addr, size)
			return addr, err
		}
	}
	return 0, nil
}

func (u *Unicorn) PackAddr(buf []byte, n uint64) error {
	if len(buf) < u.Bsz {
		return errors.New("Buffer too small.")
	}
	if u.Bits == 64 {
		// TODO: endian
		// TODO: just save a pointer/wrapper to these functions?
		binary.LittleEndian.PutUint64(buf, n)
	} else {
		binary.LittleEndian.PutUint32(buf, uint32(n))
	}
	return nil
}

func (u *Unicorn) UnpackAddr(buf []byte) uint64 {
	// TODO: endian
	if u.Bits == 64 {
		return binary.LittleEndian.Uint64(buf)
	} else {
		return uint64(binary.LittleEndian.Uint32(buf))
	}
}

func (u *Unicorn) Push(n uint64) error {
	sp, err := u.RegRead(u.Arch.SP)
	if err != nil {
		return err
	}
	if err := u.RegWrite(u.Arch.SP, sp-uint64(u.Bsz)); err != nil {
		return err
	}
	var buf [8]byte
	u.PackAddr(buf[:u.Bsz], n)
	return u.MemWrite(sp-uint64(u.Bsz), buf[:u.Bsz])
}

func (u *Unicorn) Pop() (uint64, error) {
	sp, err := u.RegRead(u.Arch.SP)
	if err != nil {
		return 0, err
	}
	var buf [8]byte
	if err := u.MemReadInto(buf[:u.Bsz], sp); err != nil {
		return 0, err
	}
	if err := u.RegWrite(u.Arch.SP, sp+uint64(u.Bsz)); err != nil {
		return 0, err
	}
	return u.UnpackAddr(buf[:u.Bsz]), nil
}
