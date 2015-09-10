package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"

	"./models"
)

type Unicorn struct {
	uc.Unicorn
	arch   *models.Arch
	OS     *models.OS
	bits   int
	Bsz    int
	order  binary.ByteOrder
	memory []mmap
}

func NewUnicorn(arch *models.Arch, os *models.OS, order binary.ByteOrder) (*Unicorn, error) {
	Uc, err := uc.NewUnicorn(arch.UC_ARCH, arch.UC_MODE)
	if err != nil {
		return nil, err
	}
	return &Unicorn{
		Unicorn: Uc,
		arch:    arch,
		OS:      os,
		bits:    arch.Bits,
		Bsz:     arch.Bits / 8,
		order:   order,
	}, nil
}

func (u *Unicorn) Arch() *models.Arch {
	return u.arch
}

func (u *Unicorn) Bits() uint {
	return uint(u.bits)
}

func (u *Unicorn) ByteOrder() binary.ByteOrder {
	return u.order
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
	return Disas(mem, addr, u.arch, u.Bsz)
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
	return u.Unicorn.MemMap(addr, size)
}

func (u *Unicorn) Mmap(addr, size uint64) (uint64, error) {
	if addr == 0 {
		addr = BASE
	}
	_, size = align(0, size, true)
	addr, size = align(addr, size)
	for i := addr; i < uint64(1)<<uint64(u.bits-1); i += UC_MEM_ALIGN {
		if u.mapping(i, size) == nil {
			err := u.MemMap(i, size)
			return i, err
		}
	}
	return 0, errors.New("Unicorn.Mmap() failed.")
}

func (u *Unicorn) MmapWrite(addr uint64, p []byte) (uint64, error) {
	addr, err := u.Mmap(addr, uint64(len(p)))
	if err != nil {
		return 0, err
	}
	return addr, u.MemWrite(addr, p)
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

func (u *Unicorn) MemReader(addr uint64) io.Reader {
	return &models.MemReader{u, addr}
}

func (u *Unicorn) MemWriter(addr uint64) io.Writer {
	return &models.MemWriter{u, addr}
}

func (u *Unicorn) PackAddr(buf []byte, n uint64) error {
	if len(buf) < u.Bsz {
		return errors.New("Buffer too small.")
	}
	if u.bits == 64 {
		u.order.PutUint64(buf, n)
	} else {
		u.order.PutUint32(buf, uint32(n))
	}
	return nil
}

func (u *Unicorn) UnpackAddr(buf []byte) uint64 {
	if u.bits == 64 {
		return u.order.Uint64(buf)
	} else {
		return uint64(u.order.Uint32(buf))
	}
}

func (u *Unicorn) PopBytes(p []byte) error {
	sp, err := u.RegRead(u.arch.SP)
	if err != nil {
		return err
	}
	if err := u.MemReadInto(p, sp); err != nil {
		return err
	}
	return u.RegWrite(u.arch.SP, sp+uint64(len(p)))
}

func (u *Unicorn) PushBytes(p []byte) error {
	sp, err := u.RegRead(u.arch.SP)
	if err != nil {
		return err
	}
	if err := u.RegWrite(u.arch.SP, sp-uint64(len(p))); err != nil {
		return err
	}
	return u.MemWrite(sp-uint64(len(p)), p)
}

func (u *Unicorn) Push(n uint64) error {
	var buf [8]byte
	u.PackAddr(buf[:u.Bsz], n)
	return u.PushBytes(buf[:u.Bsz])
}

func (u *Unicorn) Pop() (uint64, error) {
	var buf [8]byte
	if err := u.PopBytes(buf[:u.Bsz]); err != nil {
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

func (u *Unicorn) RegDump() ([]models.RegVal, error) {
	return u.arch.RegDump(u)
}
