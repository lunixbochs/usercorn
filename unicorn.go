package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	uc "github.com/lunixbochs/unicorn"

	"./models"
)

type Unicorn struct {
	*uc.Uc
	Arch   *models.Arch
	OS     *models.OS
	Bits   int
	Bsz    int
	memory []mmap
}

func NewUnicorn(arch *models.Arch, os *models.OS) (*Unicorn, error) {
	Uc, err := uc.NewUc(arch.UC_ARCH, arch.UC_MODE)
	if err != nil {
		return nil, err
	}
	return &Unicorn{
		Uc:   Uc,
		Arch: arch,
		OS:   os,
		Bits: arch.Bits,
		Bsz:  arch.Bits / 8,
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

func (u *Unicorn) Disas(addr, size uint64) (string, error) {
	mem, err := u.MemRead(addr, size)
	if err != nil {
		return "", err
	}
	return Disas(mem, addr, u.Arch)
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
	for i := addr; i < uint64(1)<<uint64(u.Bits-1); i += UC_MEM_ALIGN {
		if u.mapping(i, size) == nil {
			err := u.MemMap(i, size)
			return i, err
		}
	}
	return 0, errors.New("Unicorn.Mmap() failed.")
}

func (u *Unicorn) MemReadStr(addr uint64) (string, error) {
	var tmp = [4]byte{1, 1, 1, 1}
	var ret []byte
	nul := []byte{0}
	for !bytes.Contains(tmp[:], nul) {
		u.MemReadInto(tmp[:], addr)
		addr += 4
		ret = append(ret, tmp[:]...)
	}
	split := bytes.Index(ret, nul)
	return string(ret[:split]), nil
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

func (u *Unicorn) ReadRegs(regs []int) ([]uint64, error) {
	ret := make([]uint64, len(regs))
	for i, reg := range regs {
		n, err := u.RegRead(reg)
		if err != nil {
			return nil, err
		}
		ret[i] = n
	}
	return ret, nil
}
