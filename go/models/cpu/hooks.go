package cpu

import (
	"github.com/pkg/errors"
)

// bunch of wrapper types
type Hook interface{}

// maybe type aliases will fix the requirement to hardcode these types
// type CodeCb func(Cpu, uint64, uint32)
// type IntrCb func(Cpu, uint32)
// type MemCb func(Cpu, int, uint64, int, int64)
// type MemFaultCb func(Cpu, int, uint64, int, int64) bool

type hookInfo struct {
	htype int
	start uint64
	end   uint64
}

func (h *hookInfo) Type() int {
	return h.htype
}

func (h *hookInfo) Contains(addr uint64) bool {
	return h.start > h.end || addr >= h.start && addr <= h.end
}

type hinfo interface {
	Type() int
}

type codeHook struct {
	hookInfo
	cb func(Cpu, uint64, uint32)
}

type intrHook struct {
	hookInfo
	cb func(Cpu, uint32)
}

type memHook struct {
	hookInfo
	cb func(Cpu, int, uint64, int, int64)
}

type memFaultHook struct {
	hookInfo
	cb func(Cpu, int, uint64, int, int64) bool
}

// real code starts here
type Hooks struct {
	cpu Cpu

	code     []*codeHook
	block    []*codeHook
	intr     []*intrHook
	mem      []*memHook
	memFault []*memFaultHook
}

// creates &Hook{}, optionally attaching to a *Mem instance
func NewHooks(cpu Cpu, mem *Mem) *Hooks {
	h := &Hooks{cpu: cpu}
	// TODO: fault hooks inside mem?
	if mem != nil {
		// mem/memsim will dispatch hooks automatically
		mem.hooks = h
	}
	return h
}

// copy-pasted from UnicornCpu
func (h *Hooks) HookAdd(htype int, cb interface{}, start uint64, end uint64, extra ...int) (Hook, error) {
	info := hookInfo{htype, start, end}
	// don't forget to set hook!
	var hook interface{}
	switch htype {
	case HOOK_BLOCK:
		hh := &codeHook{info, cb.(func(Cpu, uint64, uint32))}
		h.block, hook = append(h.block, hh), hh

	case HOOK_CODE:
		hh := &codeHook{info, cb.(func(Cpu, uint64, uint32))}
		h.code, hook = append(h.code, hh), hh

	case HOOK_INTR:
		hh := &intrHook{info, cb.(func(Cpu, uint32))}
		h.intr, hook = append(h.intr, hh), hh

	case HOOK_MEM_READ, HOOK_MEM_WRITE, HOOK_MEM_READ | HOOK_MEM_WRITE:
		hh := &memHook{info, cb.(func(Cpu, int, uint64, int, int64))}
		h.mem, hook = append(h.mem, hh), hh

	case HOOK_INSN:
		// TODO: allow instruction hooking
		panic("instruction hooking not implemented")

	case HOOK_MEM_ERR:
		hh := &memFaultHook{info, cb.(func(Cpu, int, uint64, int, int64) bool)}
		h.memFault, hook = append(h.memFault, hh), hh

	default:
		return 0, errors.New("Unknown hook type.")
	}
	return hook, nil
}

func (h *Hooks) HookDel(hh Hook) error {
	// FIXME: failed interface conversion will panic but could error instead

	// FIXME? this is really verbose
	// I could switch to a single hook array but it would be slower
	// del could be done with reflection.
	switch hh.(hinfo).Type() {
	case HOOK_BLOCK:
		var tmp []*codeHook
		for _, v := range h.block {
			if v != hh {
				tmp = append(tmp, v)
			}
		}
		h.block = tmp
	case HOOK_CODE:
		var tmp []*codeHook
		for _, v := range h.code {
			if v != hh {
				tmp = append(tmp, v)
			}
		}
		h.code = tmp
	case HOOK_INTR:
		var tmp []*intrHook
		for _, v := range h.intr {
			if v != hh {
				tmp = append(tmp, v)
			}
		}
		h.intr = tmp
	case HOOK_MEM_READ, HOOK_MEM_WRITE, HOOK_MEM_READ | HOOK_MEM_WRITE:
		var tmp []*memHook
		for _, v := range h.mem {
			if v != hh {
				tmp = append(tmp, v)
			}
		}
		h.mem = tmp
	case HOOK_MEM_ERR:
		var tmp []*memFaultHook
		for _, v := range h.memFault {
			if v != hh {
				tmp = append(tmp, v)
			}
		}
		h.memFault = tmp
	}
	return nil
}

func (h *Hooks) OnBlock(addr uint64, size uint32) {
	for _, v := range h.block {
		if v.Contains(addr) {
			v.cb(h.cpu, addr, size)
		}
	}
}

func (h *Hooks) OnCode(addr uint64, size uint32) {
	for _, v := range h.code {
		if v.Contains(addr) {
			v.cb(h.cpu, addr, size)
		}
	}
}

func (h *Hooks) OnIntr(intno uint32) {
	for _, v := range h.intr {
		v.cb(h.cpu, intno)
	}
}

func (h *Hooks) OnMem(access int, addr uint64, size int, val int64) {
	for _, v := range h.mem {
		if v.Contains(addr) {
			v.cb(h.cpu, access, addr, size, val)
		}
	}
}

func (h *Hooks) OnFault(access int, addr uint64, size int, val int64) bool {
	for _, v := range h.memFault {
		if v.Contains(addr) {
			if v.cb(h.cpu, access, addr, size, val) {
				return true
			}
		}
	}
	return false
}
