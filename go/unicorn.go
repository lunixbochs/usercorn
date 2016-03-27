package usercorn

import (
	"encoding/binary"
	"errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

type Unicorn struct {
	uc.Unicorn
	arch   *models.Arch
	os     *models.OS
	bits   int
	Bsz    int
	order  binary.ByteOrder
	memory []*models.Mmap
}

func NewUnicorn(arch *models.Arch, os *models.OS, order binary.ByteOrder) (*Unicorn, error) {
	Uc, err := uc.NewUnicorn(arch.UC_ARCH, arch.UC_MODE)
	if err != nil {
		return nil, err
	}
	return &Unicorn{
		Unicorn: Uc,
		arch:    arch,
		os:      os,
		bits:    arch.Bits,
		Bsz:     arch.Bits / 8,
		order:   order,
	}, nil
}

func (u *Unicorn) Arch() *models.Arch {
	return u.arch
}

func (u *Unicorn) OS() string {
	return u.os.Name
}

func (u *Unicorn) Bits() uint {
	return uint(u.bits)
}

func (u *Unicorn) ByteOrder() binary.ByteOrder {
	return u.order
}

func (u *Unicorn) mapping(addr, size uint64) *models.Mmap {
	for _, m := range u.memory {
		if addr < m.Addr && addr+size > m.Addr {
			return m
		}
		if addr >= m.Addr && addr < m.Addr+m.Size {
			return m
		}
	}
	return nil
}

func (u *Unicorn) Disas(addr, size uint64) (string, error) {
	mem, err := u.MemRead(addr, size)
	if err != nil {
		return "", err
	}
	return models.Disas(mem, addr, u.arch, u.Bsz)
}

func (u *Unicorn) MemMapProt(addr, size uint64, prot int) error {
	m := u.mapping(addr, size)
	for m != nil {
		a, b := m.Addr, m.Addr+m.Size
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
	addr, size = align(addr, size, true)
	u.memory = append(u.memory, &models.Mmap{Addr: addr, Size: size, Prot: prot})
	return u.Unicorn.MemMap(addr, size)
}

func (u *Unicorn) MemMap(addr, size uint64) error {
	return u.MemMapProt(addr, size, uc.PROT_ALL)
}

func (u *Unicorn) MemProtect(addr, size uint64, prot int) error {
	if mmap := u.mapping(addr, size); mmap != nil {
		mmap.Prot = prot
	}
	return u.Unicorn.MemProtect(addr, size, prot)
}

func (u *Unicorn) MemUnmap(addr, size uint64) error {
	err := u.Unicorn.MemUnmap(addr, size)
	if err != nil {
		return err
	}
	for {
		mmap := u.mapping(addr, size)
		if mmap == nil {
			break
		}
		left := mmap.Addr
		right := left + mmap.Size
		// if unmap overlaps an edge, shrink that edge
		if addr <= left && addr+size > left {
			left = addr + size
		}
		if addr < right && addr+size >= right {
			right = addr
		}
		inMiddle := left < addr && right > addr+size
		// if our mapping now has size <= 0, delete it
		// also delete if the unmap was fully in the middle (as we'll split the mapping into each side)
		if left >= right || inMiddle {
			// delete by copying to a new array
			tmp := make([]*models.Mmap, 0, len(u.memory)-1)
			for _, v := range u.memory {
				if v != mmap {
					tmp = append(tmp, v)
				}
			}
			u.memory = tmp
		} else {
			// otherwise resize our existing mapping
			mmap.Addr = left
			mmap.Size = right - left
		}
		// if unmap range is fully in the middle, split and create a new mapping for each side
		if inMiddle {
			left := &models.Mmap{
				Addr: mmap.Addr, Size: addr - mmap.Addr,
				Prot: mmap.Prot, File: mmap.File, Desc: mmap.Desc,
			}
			right := &models.Mmap{
				Addr: addr + size, Size: (mmap.Addr + mmap.Size) - (addr + size),
				Prot: mmap.Prot, File: mmap.File, Desc: mmap.Desc,
			}
			u.memory = append(u.memory, left)
			u.memory = append(u.memory, right)
		}

	}
	return err
}

func (u *Unicorn) Mappings() []*models.Mmap {
	return u.memory
}

func (u *Unicorn) MemReserve(addr, size uint64) (*models.Mmap, error) {
	if addr == 0 {
		addr = BASE
	}
	addr, size = align(addr, size, true)
	for i := addr; i < uint64(1)<<uint64(u.bits-1); i += UC_MEM_ALIGN {
		if u.mapping(i, size) == nil {
			mmap := &models.Mmap{Addr: i, Size: size, Prot: uc.PROT_ALL}
			u.memory = append(u.memory, mmap)
			return mmap, nil
		}
	}
	return nil, errors.New("failed to reserve memory")
}

func (u *Unicorn) Mmap(addr, size uint64) (*models.Mmap, error) {
	mmap, err := u.MemReserve(addr, size)
	if err != nil {
		return nil, err
	}
	return mmap, u.Unicorn.MemMap(mmap.Addr, mmap.Size)
}

func (u *Unicorn) MmapWrite(addr uint64, p []byte) (uint64, error) {
	mmap, err := u.Mmap(addr, uint64(len(p)))
	if err != nil {
		return 0, err
	}
	return mmap.Addr, u.MemWrite(mmap.Addr, p)
}

func (u *Unicorn) PackAddr(buf []byte, n uint64) ([]byte, error) {
	if len(buf) < u.Bsz {
		return nil, errors.New("Buffer too small.")
	}
	if u.bits == 64 {
		u.order.PutUint64(buf[:u.Bsz], n)
	} else {
		u.order.PutUint32(buf[:u.Bsz], uint32(n))
	}
	return buf[:u.Bsz], nil
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

func (u *Unicorn) PushBytes(p []byte) (uint64, error) {
	sp, err := u.RegRead(u.arch.SP)
	if err != nil {
		return 0, err
	}
	sp -= uint64(len(p))
	if err := u.RegWrite(u.arch.SP, sp); err != nil {
		return 0, err
	}
	return sp, u.MemWrite(sp, p)
}

func (u *Unicorn) Push(n uint64) (uint64, error) {
	var tmp [8]byte
	buf, _ := u.PackAddr(tmp[:], n)
	return u.PushBytes(buf)
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
