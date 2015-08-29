package main

import (
	"encoding/binary"
	"errors"
	uc "github.com/lunixbochs/unicorn"

	"./arch/arch"
)

type mmap struct {
	Start, Size uint64
}

type Unicorn struct {
	*uc.Uc
	Arch   arch.Arch
	Bits   int
	Bsz    int
	memory []mmap
}

func NewUnicorn(a arch.Arch) (*Unicorn, error) {
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

func (u *Unicorn) mapping(addr, size uint64) mmap {
	for _, m := range u.memory {
		if addr < m.Start && addr+size > m.Start {
			return m
		}
		if addr >= m.Start && addr < m.Start+m.Size {
			return m
		}
	}
	return mmap{}
}

func (u *Unicorn) MemMap(addr, size uint64) error {
	return nil
}

func (u *Unicorn) Mmap(addr, size uint64) (uint64, error) {
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
