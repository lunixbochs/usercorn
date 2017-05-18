package repl

import (
	"fmt"
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/luaish-luar"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

func bindUsercorn(L *LuaRepl) error {
	b := &ubinding{L, L.u}
	mod := L.SetFuncs(L.NewTable(), b.Exports())
	L.SetGlobal("u", mod)
	L.SetGlobal("us", luar.New(L.LState, L.u))
	return nil
}

type ubinding struct {
	L *LuaRepl
	u models.Usercorn
}

func (b *ubinding) Exports() map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		"mem_map":   b.MemMap,
		"mem_prot":  b.MemProt,
		"mem_unmap": b.MemUnmap,

		"mem_read":  b.MemRead,
		"mem_write": b.MemWrite,

		"reg_read":  b.RegRead,
		"reg_write": b.RegWrite,

		"start": b.Start,
		"stop":  b.Stop,

		"hook_add": b.HookAdd,
		"hook_del": b.HookDel,

		"context_save":    b.ContextSave,
		"context_restore": b.ContextRestore,

		"close": b.Close,
	}
}

func (b *ubinding) checkErr(err error) {
	if err != nil {
		b.L.RaiseError(err.Error())
	}
}

func (b *ubinding) MemMap(L *lua.LState) int {
	addr, size, prot := L.CheckUint64(1), L.CheckUint64(2), L.CheckInt(3)
	b.checkErr(b.u.MemMapProt(addr, size, prot))
	return 0
}

func (b *ubinding) MemProt(L *lua.LState) int {
	addr, size, prot := L.CheckUint64(1), L.CheckUint64(2), L.CheckInt(3)
	b.checkErr(b.u.MemProt(addr, size, prot))
	return 0
}

func (b *ubinding) MemUnmap(L *lua.LState) int {
	addr, size := L.CheckUint64(1), L.CheckUint64(2)
	b.checkErr(b.u.MemUnmap(addr, size))
	return 0
}

func (b *ubinding) MemRead(L *lua.LState) int {
	addr, size := L.CheckUint64(1), L.CheckUint64(2)
	mem, err := b.u.MemRead(addr, size)
	b.checkErr(err)
	L.Push(lua.LString(mem))
	return 1
}

func (b *ubinding) MemWrite(L *lua.LState) int {
	addr, data := L.CheckUint64(1), L.CheckString(2)
	b.checkErr(b.u.MemWrite(addr, []byte(data)))
	return 0
}

// lua doesn't have reg enums
func (b *ubinding) RegRead(L *lua.LState) int {
	enum := L.CheckInt(1)
	val, err := b.u.RegRead(enum)
	b.checkErr(err)
	L.Push(lua.LNumber(val))
	return 1
}

func (b *ubinding) RegWrite(L *lua.LState) int {
	enum, val := L.CheckInt(1), L.CheckUint64(2)
	b.checkErr(b.u.RegWrite(enum, val))
	return 0
}

func (b *ubinding) Start(L *lua.LState) int {
	start, end := L.CheckUint64(1), L.CheckUint64(2)
	b.checkErr(b.u.Start(start, end))
	return 0
}

func (b *ubinding) Stop(L *lua.LState) int {
	b.checkErr(b.u.Stop())
	return 0
}

// copy-pasted from models/cpu.Cpu
// func (h *Hooks) HookAdd(htype int, cb interface{}, start uint64, end uint64, extra ...int) (Hook, error) {
func (b *ubinding) HookAdd(L *lua.LState) int {
	htype, fn := L.CheckInt(1), L.CheckFunction(2)
	start := uint64(1)
	end := uint64(0)
	if L.GetTop() >= 4 {
		start, end = L.CheckUint64(3), L.CheckUint64(4)
	}
	luap := lua.P{Fn: fn, NRet: 0, Protect: true}

	var cb interface{}
	switch htype {
	case cpu.HOOK_CODE, cpu.HOOK_BLOCK:
		cb = func(_ cpu.Cpu, addr uint64, size uint32) {
			laddr, lsize := lua.LNumber(addr), lua.LNumber(size)
			L.SetGlobal("addr", laddr)
			L.SetGlobal("size", lsize)
			if err := L.CallByParam(luap, laddr, lsize); err != nil {
				fmt.Println(err)
			}
		}
	case cpu.HOOK_INTR:
		cb = func(_ cpu.Cpu, intno uint32) {
			lintno := lua.LNumber(intno)
			L.SetGlobal("intno", lintno)
			if err := L.CallByParam(luap, lintno); err != nil {
				fmt.Println(err)
			}
		}
	case cpu.HOOK_MEM_READ, cpu.HOOK_MEM_WRITE, cpu.HOOK_MEM_READ | cpu.HOOK_MEM_WRITE:
		cb = func(_ cpu.Cpu, access int, addr uint64, size int, val int64) {
			laccess, laddr, lsize, lval := lua.LNumber(access), lua.LNumber(addr), lua.LNumber(size), lua.LNumber(val)
			L.SetGlobal("access", laccess)
			L.SetGlobal("addr", laddr)
			L.SetGlobal("size", lsize)
			L.SetGlobal("val", lval)
			if err := L.CallByParam(luap, laccess, laddr, lsize, lval); err != nil {
				fmt.Println(err)
			}
		}
	case cpu.HOOK_INSN:
		// TODO: allow instruction hooking
		panic("instruction hooking not implemented")
	case cpu.HOOK_MEM_ERR:
		cb = func(_ cpu.Cpu, access int, addr uint64, size int, val int64) bool {
			laccess, laddr, lsize, lval := lua.LNumber(access), lua.LNumber(addr), lua.LNumber(size), lua.LNumber(val)
			L.SetGlobal("access", laccess)
			L.SetGlobal("addr", laddr)
			L.SetGlobal("size", lsize)
			L.SetGlobal("val", lval)
			luap.NRet = 1
			if err := L.CallByParam(luap, lua.LNumber(access), lua.LNumber(addr), lua.LNumber(size), lua.LNumber(val)); err != nil {
				fmt.Println(err)
				return false
			}
			return L.CheckBool(1)
		}
	default:
		L.RaiseError("Unknown hook type: %d", htype)
	}
	hh, err := b.u.HookAdd(htype, cb, start, end)
	b.checkErr(err)

	ptr := L.NewUserData()
	ptr.Value = hh
	L.Push(ptr)
	return 1
}

func (b *ubinding) HookDel(L *lua.LState) int {
	hh := L.CheckUserData(1)
	b.u.HookDel(hh.Value.(cpu.Hook))
	return 0
}

func (b *ubinding) ContextSave(L *lua.LState) int {
	ctx, err := b.u.ContextSave(nil)
	b.checkErr(err)
	ptr := L.NewUserData()
	ptr.Value = ctx
	L.Push(ptr)
	return 1
}

func (b *ubinding) ContextRestore(L *lua.LState) int {
	ptr := L.CheckUserData(1)
	b.u.ContextRestore(ptr.Value)
	return 0
}

func (b *ubinding) Close(L *lua.LState) int {
	b.checkErr(b.u.Close())
	return 0
}
