package unicorn

import (
	"github.com/pkg/errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Builder struct {
	Arch, Mode int
}

func (b *Builder) New() (cpu.Cpu, error) {
	u, err := uc.NewUnicorn(b.Arch, b.Mode)
	if err != nil {
		return nil, errors.Wrap(err, "NewUnicorn() failed")
	}
	return &UnicornCpu{u}, nil
}

type UnicornCpu struct {
	uc.Unicorn
}

func (u *UnicornCpu) Backend() interface{} {
	return u.Unicorn
}

func (u *UnicornCpu) ContextSave(reuse interface{}) (interface{}, error) {
	return u.Unicorn.ContextSave(reuse.(uc.Context))
}

func (u *UnicornCpu) ContextRestore(ctx interface{}) error {
	return u.Unicorn.ContextRestore(ctx.(uc.Context))
}

func (u *UnicornCpu) HookAdd(htype int, cb interface{}, start uint64, end uint64, extra ...int) (cpu.Hook, error) {
	// have to wrap all hooks to conform to Cpu interface :(
	// if I fork Unicorn bindings I can remove the cpu arg to make this easier
	var wrap interface{}
	switch htype {
	case cpu.HOOK_BLOCK, cpu.HOOK_CODE:
		cbc := cb.(func(cpu.Cpu, uint64, uint32))
		wrap = func(_ uc.Unicorn, addr uint64, size uint32) { cbc(u, addr, size) }

	case cpu.HOOK_MEM_READ, cpu.HOOK_MEM_WRITE, cpu.HOOK_MEM_READ | cpu.HOOK_MEM_WRITE:
		cbc := cb.(func(cpu.Cpu, int, uint64, int, int64))
		wrap = func(_ uc.Unicorn, access int, addr uint64, size int, val int64) { cbc(u, access, addr, size, val) }

	case cpu.HOOK_INTR:
		cbc := cb.(func(cpu.Cpu, uint32))
		wrap = func(_ uc.Unicorn, intno uint32) { cbc(u, intno) }

	case cpu.HOOK_INSN:
		// don't need to wrap HOOK_INSN because only arch-aware callers will use it
		wrap = cb

	default:
		// special case for mask
		if htype&(uc.HOOK_MEM_READ_UNMAPPED|uc.HOOK_MEM_WRITE_UNMAPPED|uc.HOOK_MEM_FETCH_UNMAPPED|
			uc.HOOK_MEM_READ_PROT|uc.HOOK_MEM_WRITE_PROT|uc.HOOK_MEM_FETCH_PROT) != 0 {

			cbc := cb.(func(cpu.Cpu, int, uint64, int, int64) bool)
			wrap = func(_ uc.Unicorn, access int, addr uint64, size int, val int64) bool {
				return cbc(u, access, addr, size, val)
			}
		} else {
			return 0, errors.New("Unknown hook type.")
		}
	}
	return u.Unicorn.HookAdd(htype, wrap, start, end, extra...)
}

func (u *UnicornCpu) HookDel(hh cpu.Hook) error {
	return u.Unicorn.HookDel(hh.(uc.Hook))
}

func (u *UnicornCpu) MemMap(addr, size uint64, prot int) error {
	return u.Unicorn.MemMapProt(addr, size, prot)
}

func (u *UnicornCpu) MemProt(addr, size uint64, prot int) error {
	return u.Unicorn.MemProtect(addr, size, prot)
}
