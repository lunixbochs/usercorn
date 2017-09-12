package usercorn

import (
	"encoding/binary"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Task struct {
	cpu.Cpu

	arch     *models.Arch
	os       *models.OS
	bits     int
	Bsz      int
	order    binary.ByteOrder
	memory   []*cpu.Page
	mapHooks []*models.MapHook
}

func NewTask(c cpu.Cpu, arch *models.Arch, os *models.OS, order binary.ByteOrder) *Task {
	return &Task{
		Cpu:   c,
		arch:  arch,
		os:    os,
		bits:  arch.Bits,
		Bsz:   arch.Bits / 8,
		order: order,
	}
}

func (t *Task) Arch() *models.Arch {
	return t.arch
}

func (t *Task) OS() string {
	return t.os.Name
}

func (t *Task) Bits() uint {
	return uint(t.bits)
}

func (t *Task) ByteOrder() binary.ByteOrder {
	return t.order
}

func (t *Task) mapping(addr, size uint64) *cpu.Page {
	for _, m := range t.memory {
		if addr < m.Addr && addr+size > m.Addr {
			return m
		}
		if addr >= m.Addr && addr < m.Addr+m.Size {
			return m
		}
	}
	return nil
}

func (t *Task) Asm(asm string, addr uint64) ([]byte, error) {
	return models.Assemble(asm, addr, t.arch)
}

func (t *Task) Dis(addr, size uint64, showBytes bool) (string, error) {
	mem, err := t.MemRead(addr, size)
	if err != nil {
		return "", err
	}
	return models.Disas(mem, addr, t.arch, showBytes, t.Bsz)
}

func (t *Task) MemMap(addr, size uint64, prot int) error {
	_, err := t.Mmap(addr, size, prot, true, "", nil)
	return err
}

func (t *Task) MemProtect(addr, size uint64, prot int) error {
	// TODO: mapping a subregion should split the mapping?
	addr, size = align(addr, size, true)
	if mmap := t.mapping(addr, size); mmap != nil {
		mmap.Prot = prot
	}
	err := t.Cpu.MemProt(addr, size, prot)
	if err == nil {
		for _, v := range t.mapHooks {
			v.Map(addr, size, prot, false, "", nil)
		}
	}
	return errors.Wrap(err, "t.MemProtect() failed")
}

func (t *Task) MemUnmap(addr, size uint64) error {
	// note: if there are errors during map, this could generate more unmap events than maps *shrug*
	for _, v := range t.mapHooks {
		v.Unmap(addr, size)
	}
	// TODO: alignment check?
	for {
		mmap := t.mapping(addr, size)
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
		// unmap in Cpu
		if left >= right {
			t.Cpu.MemUnmap(mmap.Addr, mmap.Size)
		} else {
			if left > mmap.Addr {
				t.Cpu.MemUnmap(mmap.Addr, left-mmap.Addr)
			}
			if right < mmap.Addr+mmap.Size {
				t.Cpu.MemUnmap(right, (mmap.Addr+mmap.Size)-right)
			}
		}
		// if our mapping now has size <= 0, delete it
		// also delete if the unmap was fully in the middle (as we'll split the mapping into each side)
		if left >= right || inMiddle {
			// delete by copying to a new array
			tmp := make([]*cpu.Page, 0, len(t.memory))
			for _, v := range t.memory {
				if v != mmap {
					tmp = append(tmp, v)
				}
			}
			t.memory = tmp
		} else {
			// otherwise resize our existing mapping
			mmap.Addr = left
			mmap.Size = right - left
		}
		// if unmap range is fully in the middle, split and create a new mapping for each side
		if inMiddle {
			t.Cpu.MemUnmap(addr, size)
			left := &cpu.Page{
				Addr: mmap.Addr, Size: addr - mmap.Addr,
				Prot: mmap.Prot, File: mmap.File, Desc: mmap.Desc,
			}
			right := &cpu.Page{
				Addr: addr + size, Size: (mmap.Addr + mmap.Size) - (addr + size),
				Prot: mmap.Prot, File: mmap.File, Desc: mmap.Desc,
			}
			t.memory = append(t.memory, left)
			t.memory = append(t.memory, right)
		}

	}
	return nil
}

func (t *Task) Mappings() []*cpu.Page {
	return t.memory
}

func (t *Task) MemReserve(addr, size uint64, fixed bool) (*cpu.Page, error) {
	if addr == 0 && !fixed {
		addr = BASE
	}
	addr, size = align(addr, size, true)
	if fixed {
		t.MemUnmap(addr, size)
		mmap := &cpu.Page{Addr: addr, Size: size, Prot: cpu.PROT_ALL}
		t.memory = append(t.memory, mmap)
		return mmap, nil
	}
	lastPage := ^uint64(0)>>uint8(64-t.bits) - UC_MEM_ALIGN + 2
	for i := addr; i < lastPage; i += UC_MEM_ALIGN {
		if t.mapping(i, size) == nil {
			mmap := &cpu.Page{Addr: i, Size: size, Prot: cpu.PROT_ALL}
			t.memory = append(t.memory, mmap)
			return mmap, nil
		}
	}
	return nil, errors.New("failed to reserve memory")
}

func (t *Task) Mmap(addr, size uint64, prot int, fixed bool, desc string, file *cpu.FileDesc) (uint64, error) {
	aligned, size := align(addr, size, true)
	if file != nil {
		file.Off += aligned - addr
	}
	mmap, err := t.MemReserve(aligned, size, fixed)
	if err != nil {
		return 0, err
	}
	mmap.Desc = desc
	mmap.File = file
	err = t.Cpu.MemMap(mmap.Addr, mmap.Size, prot)
	if err == nil {
		for _, v := range t.mapHooks {
			v.Map(addr, size, prot, true, desc, file)
		}
	}
	return mmap.Addr, err
}

func (t *Task) Malloc(size uint64) (uint64, error) {
	return t.Mmap(0, size, cpu.PROT_READ|cpu.PROT_WRITE, false, "", nil)
}

func (t *Task) PackAddr(buf []byte, n uint64) ([]byte, error) {
	return cpu.PackUint(t.order, t.Bsz, buf, n)
}

func (t *Task) UnpackAddr(buf []byte) uint64 {
	n, err := cpu.UnpackUint(t.order, t.Bsz, buf)
	if err != nil {
		panic(err)
	}
	return n
}

func (t *Task) PopBytes(p []byte) error {
	sp, err := t.RegRead(t.arch.SP)
	if err != nil {
		return err
	}
	if err := t.MemReadInto(p, sp); err != nil {
		return err
	}
	return t.RegWrite(t.arch.SP, sp+uint64(len(p)))
}

func (t *Task) PushBytes(p []byte) (uint64, error) {
	sp, err := t.RegRead(t.arch.SP)
	if err != nil {
		return 0, err
	}
	sp -= uint64(len(p))
	if err := t.RegWrite(t.arch.SP, sp); err != nil {
		return 0, err
	}
	return sp, t.MemWrite(sp, p)
}

func (t *Task) Push(n uint64) (uint64, error) {
	var tmp [8]byte
	buf, _ := t.PackAddr(tmp[:], n)
	return t.PushBytes(buf)
}

func (t *Task) Pop() (uint64, error) {
	var buf [8]byte
	if err := t.PopBytes(buf[:t.Bsz]); err != nil {
		return 0, err
	}
	return t.UnpackAddr(buf[:t.Bsz]), nil
}

func (t *Task) RegReadBatch(regs []int) ([]uint64, error) {
	// FIXME
	// ret, err := t.Cpu.RegReadBatch(regs)
	vals := make([]uint64, len(regs))
	for i, enum := range regs {
		val, err := t.Cpu.RegRead(enum)
		if err != nil {
			return nil, errors.Wrap(err, "t.RegReadBatch() failed")
		}
		vals[i] = val
	}
	return vals, nil
}

func (t *Task) RegDump() ([]models.RegVal, error) {
	return t.arch.RegDump(t.Cpu)
}

func (t *Task) RegRead(enum int) (uint64, error) {
	val, err := t.Cpu.RegRead(enum)
	return val, errors.Wrap(err, "t.RegRead() failed")
}

func (t *Task) RegWrite(enum int, val uint64) error {
	err := t.Cpu.RegWrite(enum, val)
	return errors.Wrap(err, "t.RegWrite() failed")
}

func (t *Task) MemRead(addr, size uint64) ([]byte, error) {
	data, err := t.Cpu.MemRead(addr, size)
	return data, errors.Wrap(err, "t.MemRead() failed")
}

func (t *Task) MemWrite(addr uint64, p []byte) error {
	err := t.Cpu.MemWrite(addr, p)
	return errors.Wrap(err, "t.MemWrite() failed")
}

func (t *Task) MemReadInto(p []byte, addr uint64) error {
	err := t.Cpu.MemReadInto(p, addr)
	return errors.Wrap(err, "t.MemReadInto() failed")
}

func (t *Task) HookMapAdd(mapCb models.MapCb, unmap models.UnmapCb) *models.MapHook {
	hook := &models.MapHook{Map: mapCb, Unmap: unmap}
	t.mapHooks = append(t.mapHooks, hook)
	return hook
}

func (t *Task) HookMapDel(hook *models.MapHook) {
	tmp := make([]*models.MapHook, 0, len(t.mapHooks)-1)
	for _, v := range t.mapHooks {
		if v != hook {
			tmp = append(tmp, v)
		}
	}
	t.mapHooks = tmp
}
