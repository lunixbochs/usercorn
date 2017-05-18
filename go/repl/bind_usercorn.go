package repl

import (
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/luaish-luar"

	"github.com/lunixbochs/usercorn/go/models"
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
	return 0
}

func (b *ubinding) RegRead(L *lua.LState) int {
	return 0
}

func (b *ubinding) RegWrite(L *lua.LState) int {
	return 0
}

func (b *ubinding) Start(L *lua.LState) int {
	return 0
}

func (b *ubinding) Stop(L *lua.LState) int {
	return 0
}

func (b *ubinding) HookAdd(L *lua.LState) int {
	return 0
}

func (b *ubinding) HookDel(L *lua.LState) int {
	return 0
}

func (b *ubinding) ContextSave(L *lua.LState) int {
	return 0
}

func (b *ubinding) ContextRestore(L *lua.LState) int {
	return 0
}

func (b *ubinding) Close(L *lua.LState) int {
	return 0
}
