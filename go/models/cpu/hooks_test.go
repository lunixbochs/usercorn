package cpu

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"testing"
)

func callAll(h *Hooks) {
	h.OnBlock(0x1000, 1)
	h.OnCode(0x1001, 2)
	h.OnIntr(3)
	h.OnMem(MEM_WRITE, 0x1002, 4, -1)
	h.OnFault(MEM_WRITE_UNMAPPED, 0x1003, 8, -2)
}

func makeHooks() (*Mem, *Hooks) {
	mem := NewMem(64, binary.LittleEndian)
	return mem, NewHooks(nil, mem)
}

// this test ensures it's safe to dispatch all hooks while empty
func TestHooksEmpty(t *testing.T) {
	_, h := makeHooks()
	callAll(h)
}

// checks if two lists of strings are equal
func strseq(a []string, b []string) error {
	if len(a) != len(b) {
		return errors.Errorf("output list length mismatch")
	}
	for i, v := range a {
		if v != b[i] {
			return errors.Errorf("output list value mismatch: %s != %s", v, b[i])
		}
	}
	return nil
}

// generic hook tests
func TestHooks(t *testing.T) {
	_, h := makeHooks()
	compare := []string{
		"block(0x1000, 0x1)", "code(0x1001, 0x2)", "intr(3)",
		"mem(17, 0x1002, 4, -0x1)", "fault(20, 0x1003, 8, -0x2)",
	}
	var results []string
	blockCb := func(_ Cpu, addr uint64, size uint32) {
		results = append(results, fmt.Sprintf("block(%#x, %#x)", addr, size))
	}
	codeCb := func(_ Cpu, addr uint64, size uint32) {
		results = append(results, fmt.Sprintf("code(%#x, %#x)", addr, size))
	}
	intrCb := func(_ Cpu, intno uint32) {
		results = append(results, fmt.Sprintf("intr(%d)", intno))
	}
	writeCb := func(_ Cpu, access int, addr uint64, size int, val int64) {
		results = append(results, fmt.Sprintf("mem(%d, %#x, %d, %#x)", access, addr, size, val))
	}
	faultCb := func(_ Cpu, access int, addr uint64, size int, val int64) bool {
		results = append(results, fmt.Sprintf("fault(%d, %#x, %d, %#x)", access, addr, size, val))
		return val == 42
	}
	var hooks []Hook
	addHooks := func(h *Hooks) {
		var hh Hook
		var err error
		if hh, err = h.HookAdd(HOOK_BLOCK, blockCb, 1, 0); err != nil {
			t.Fatal(err)
		}
		hooks = append(hooks, hh)
		if hh, err = h.HookAdd(HOOK_CODE, codeCb, 1, 0); err != nil {
			t.Fatal(err)
		}
		hooks = append(hooks, hh)
		if hh, err = h.HookAdd(HOOK_INTR, intrCb, 1, 0); err != nil {
			t.Fatal(err)
		}
		hooks = append(hooks, hh)
		if hh, err = h.HookAdd(HOOK_MEM_WRITE, writeCb, 1, 0); err != nil {
			t.Fatal(err)
		}
		hooks = append(hooks, hh)
		if hh, err = h.HookAdd(HOOK_MEM_ERR, faultCb, 1, 0); err != nil {
			t.Fatal(err)
		}
		hooks = append(hooks, hh)
	}
	removeHooks := func(h *Hooks) {
		for _, v := range hooks {
			if err := h.HookDel(v); err != nil {
				t.Fatal(err)
			}
		}
		hooks = nil
	}
	// test add, call
	addHooks(h)
	callAll(h)

	if err := strseq(results, compare); err != nil {
		t.Fatal(err)
	}
	results = nil

	// test remove, add, remove, add, call
	removeHooks(h)
	addHooks(h)
	removeHooks(h)
	addHooks(h)
	callAll(h)

	if err := strseq(results, compare); err != nil {
		t.Fatal(err)
	}
	results = nil

	// test remove, remove, add, add, call
	removeHooks(h)
	removeHooks(h)
	addHooks(h)
	addHooks(h)
	callAll(h)

	compare2 := make([]string, 0, len(compare)*2)
	for _, v := range compare {
		compare2 = append(append(compare2, v), v)
	}
	if err := strseq(results, compare2); err != nil {
		t.Fatal(err)
	}
	results = nil

	if h.OnFault(MEM_WRITE_UNMAPPED, 0, 0, 42) != true {
		t.Fatal("OnFault positive return does not seem to work")
	}
	if h.OnFault(MEM_WRITE_UNMAPPED, 0, 0, 0) != false {
		t.Fatal("OnFault negative return does not seem to work")
	}
}

// positive and negative tests for each hook type with start-end range enabled
func TestHookRange(t *testing.T) {
	_, h := makeHooks()
	// we should get 0x1000-0x1fff results, but not the 0x0 or 0x2000 results
	compare := []string{
		"block(0x1000, 0x1)", "code(0x1000, 0x1)",
		"mem(17, 0x1000, 8, 0x0)", "fault(20, 0x1000, 8, 0x0)",
		"block(0x1fff, 0x1)",
	}
	var results []string
	blockCb := func(_ Cpu, addr uint64, size uint32) {
		results = append(results, fmt.Sprintf("block(%#x, %#x)", addr, size))
	}
	codeCb := func(_ Cpu, addr uint64, size uint32) {
		results = append(results, fmt.Sprintf("code(%#x, %#x)", addr, size))
	}
	writeCb := func(_ Cpu, access int, addr uint64, size int, val int64) {
		results = append(results, fmt.Sprintf("mem(%d, %#x, %d, %#x)", access, addr, size, val))
	}
	faultCb := func(_ Cpu, access int, addr uint64, size int, val int64) bool {
		results = append(results, fmt.Sprintf("fault(%d, %#x, %d, %#x)", access, addr, size, val))
		return false
	}
	if _, err := h.HookAdd(HOOK_BLOCK, blockCb, 0x1000, 0x1fff); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HookAdd(HOOK_CODE, codeCb, 0x1000, 0x1fff); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HookAdd(HOOK_MEM_WRITE, writeCb, 0x1000, 0x1fff); err != nil {
		t.Fatal(err)
	}
	if _, err := h.HookAdd(HOOK_MEM_ERR, faultCb, 0x1000, 0x1fff); err != nil {
		t.Fatal(err)
	}
	for addr := uint64(0); addr < 0x4000; addr += 0x1000 {
		h.OnBlock(addr, 1)
		h.OnCode(addr, 1)
		h.OnMem(MEM_WRITE, addr, 8, 0)
		h.OnFault(MEM_WRITE_UNMAPPED, addr, 8, 0)
	}
	h.OnBlock(0x1fff, 1)
	if err := strseq(results, compare); err != nil {
		t.Fatal(err)
	}
	results = nil
}

func BenchmarkHook(b *testing.B) {
	_, h := makeHooks()
	codeCb := func(_ Cpu, addr uint64, size uint32) {}
	if _, err := h.HookAdd(HOOK_CODE, codeCb, 0x1000, 0x1fff); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.OnCode(0x1000, 1)
	}
}
