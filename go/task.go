package usercorn

import (
	"encoding/binary"
	"github.com/pkg/errors"
	"sort"

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
	memsim   cpu.MemSim
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

func (t *Task) MemProt(addr, size uint64, prot int) error {
	addr, size = align(addr, size, true)
	t.memsim.Prot(addr, size, prot)
	err := t.Cpu.MemProt(addr, size, prot)
	if err == nil {
		for _, v := range t.mapHooks {
			v.Prot(addr, size, prot)
		}
	}
	return errors.Wrap(err, "t.MemProt() failed")
}

func (t *Task) MemUnmap(addr, size uint64) error {
	addr, size = align(addr, size, true)
	for _, mm := range t.memsim.Mem.FindRange(addr, size) {
		t.Cpu.MemUnmap(mm.Addr, mm.Size)
		for _, v := range t.mapHooks {
			v.Unmap(mm.Addr, mm.Size)
		}
	}
	t.memsim.Unmap(addr, size)
	return nil
}

func (t *Task) Mappings() cpu.Pages {
	return t.memsim.Mem
}

func (t *Task) MemReserve(addr, size uint64, fixed bool) (*cpu.Page, error) {
	if addr == 0 && !fixed {
		addr = BASE
	}
	addr, size = align(addr, size, true)
	if fixed {
		t.MemUnmap(addr, size)
		page := &cpu.Page{Addr: addr, Size: size, Prot: cpu.PROT_NONE}
		return page, nil
	}
	lastPage := ^uint64(0)>>uint8(64-t.bits) - UC_MEM_ALIGN + 2
	for i := addr; i < lastPage; i += UC_MEM_ALIGN {
		if len(t.memsim.Mem.FindRange(i, size)) == 0 {
			page := &cpu.Page{Addr: i, Size: size, Prot: cpu.PROT_NONE}
			return page, nil
		}
	}
	return nil, errors.New("failed to reserve memory")
}

func (t *Task) Mmap(addr, size uint64, prot int, fixed bool, desc string, file *cpu.FileDesc) (uint64, error) {
	aligned, size := align(addr, size, true)
	if file != nil {
		file.Off += aligned - addr
	}
	page, err := t.MemReserve(aligned, size, fixed)
	if err != nil {
		return 0, err
	}
	page.Desc = desc
	page.File = file
	page.Prot = prot
	err = t.Cpu.MemMap(page.Addr, page.Size, prot)
	if err == nil {
		t.memsim.Mem = append(t.memsim.Mem, page)
		sort.Sort(t.memsim.Mem)
		for _, v := range t.mapHooks {
			v.Map(page.Addr, page.Size, prot, desc, file)
		}
	}
	return page.Addr, err
}

func (t *Task) Malloc(size uint64, desc string) (uint64, error) {
	return t.Mmap(0, size, cpu.PROT_READ|cpu.PROT_WRITE, false, desc, nil)
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

func (t *Task) HookMapAdd(mapCb models.MapCb, unmap models.UnmapCb, prot models.ProtCb) *models.MapHook {
	hook := &models.MapHook{Map: mapCb, Unmap: unmap, Prot: prot}
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
