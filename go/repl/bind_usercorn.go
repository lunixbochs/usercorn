package repl

import (
	"fmt"
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/luaish-luar"
	"strconv"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

func bindUsercorn(L *LuaRepl) error {
	b := &ubind{L: L, u: L.u}
	mod := L.SetFuncs(L.NewTable(), b.Exports())
	L.SetGlobal("u", mod)
	b.mod = mod
	L.SetGlobal("us", luar.New(L.LState, L.u))
	return nil
}

type ubind struct {
	L   *LuaRepl
	u   models.Usercorn
	mod *lua.LTable
}

func (b *ubind) Exports() map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		// models.Task interface
		"asm": b.Asm,
		"dis": b.Dis,
		"ins": b.Ins,

		// bonus features
		"step":        b.Step,
		"continue":    b.Continue,
		"rewind_n":    b.RewindN,
		"rewind_addr": b.RewindAddr,

		// cpu.Cpu interface
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

func (b *ubind) checkErr(err error) {
	if err != nil {
		b.L.RaiseError(err.Error())
	}
}

// models.Task interface

func (b *ubind) Asm(L *lua.LState) int {
	asm, addr := L.CheckString(1), L.CheckUint64(2)
	code, err := b.u.Asm(asm, addr)
	b.checkErr(err)
	L.Push(lua.LString(code))
	return 1
}

func disToLua(L *LuaRepl, dis []models.Ins) []*lua.LTable {
	ret := make([]*lua.LTable, len(dis))
	for i, v := range dis {
		ins := L.NewTable()
		ins.RawSetString("addr", lua.LNumber(v.Addr()))
		ins.RawSetString("name", lua.LString(v.Mnemonic()))
		ins.RawSetString("op_str", lua.LString(v.OpStr()))
		ins.RawSetString("bytes", lua.LString(v.Bytes()))

		ops := L.NewTable()
		for j, s := range strings.Split(v.OpStr(), ",") {
			s = strings.TrimSpace(s)
			if n, err := strconv.ParseUint(s, 0, 64); err == nil {
				ops.RawSetInt(j+1, lua.LNumber(n))
			} else {
				ops.RawSetInt(j+1, lua.LString(s))
			}
		}
		ins.RawSetString("ops", ops)
		ret[i] = ins
	}
	return ret
}

func (b *ubind) dis(addr, size uint64) []*lua.LTable {
	L := b.L
	arch := b.u.Arch()
	if arch.Dis == nil {
		L.RaiseError("arch<%T>.Dis not initialized", arch)
	}
	mem, err := b.u.DirectRead(addr, size)
	b.checkErr(err)
	dis, err := arch.Dis.Dis(mem, addr)
	b.checkErr(err)
	return disToLua(L, dis)
}

func (b *ubind) Dis(L *lua.LState) int {
	addr, size := L.CheckUint64(1), L.CheckUint64(2)
	insns := b.dis(addr, size)
	ret := L.NewTable()
	for i, ins := range insns {
		ret.RawSetInt(i+1, ins)
	}
	L.Push(ret)
	return 1
}

func (b *ubind) Ins(L *lua.LState) int {
	// TODO: *last* PC? or turn the prompt into the current disassembly
	r, _ := b.u.RegRead(b.u.Arch().PC)
	dis := b.dis(r, 16)
	if len(dis) > 0 {
		L.Push(dis[0])
		return 1
	}
	return 0
}

// bonus features

// Steps the CPU by <n> instructions
func (b *ubind) Step(L *lua.LState) int {
	b.L.EnvFromLua()
	steps := 1
	if L.GetTop() > 0 {
		steps = L.CheckInt(1)
	}

	i := 0
	hh, err := b.u.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
		i++
		if i > steps {
			b.u.Stop()
		}
	}, 1, 0)
	b.checkErr(err)

	/* NOTE: How to make an async step:
	b.mod.RawSetString("running", lua.LTrue)
	go func() {
		b.u.Gate().UnlockStopRelock()
		b.mod.RawSetString("running", lua.LFalse)
		b.u.HookDel(hh)
	}()
	*/
	b.u.Gate().UnlockStopRelock()
	b.u.HookDel(hh)
	b.L.EnvToLua()
	return 0
}

// Resumes execution
func (b *ubind) Continue(L *lua.LState) int {
	b.L.EnvFromLua()
	/* NOTE: How to make an async continue:
	b.mod.RawSetString("running", lua.LTrue)
	go func() {
		b.u.Gate().UnlockStopRelock()
		b.mod.RawSetString("running", lua.LFalse)
	}()
	*/
	b.u.Gate().UnlockStopRelock()
	b.L.EnvToLua()
	return 0
}

// Rewinds the CPU by <n> instructions
func (b *ubind) RewindN(L *lua.LState) int {
	n := L.CheckUint64(1)
	b.checkErr(b.u.Rewind(n, 0))
	b.L.EnvToLua()
	return 0
}

// Rewinds the cpu to the first time pc == addr
func (b *ubind) RewindAddr(L *lua.LState) int {
	addr := L.CheckUint64(1)
	b.checkErr(b.u.Rewind(0, addr))
	b.L.EnvToLua()
	return 0
}

// cpu.Cpu interface

func (b *ubind) MemMap(L *lua.LState) int {
	addr, size, prot := L.CheckUint64(1), L.CheckUint64(2), L.CheckInt(3)
	b.checkErr(b.u.MemMapProt(addr, size, prot))
	return 0
}

func (b *ubind) MemProt(L *lua.LState) int {
	addr, size, prot := L.CheckUint64(1), L.CheckUint64(2), L.CheckInt(3)
	b.checkErr(b.u.MemProt(addr, size, prot))
	return 0
}

func (b *ubind) MemUnmap(L *lua.LState) int {
	addr, size := L.CheckUint64(1), L.CheckUint64(2)
	b.checkErr(b.u.MemUnmap(addr, size))
	return 0
}

func (b *ubind) MemRead(L *lua.LState) int {
	addr, size := L.CheckUint64(1), L.CheckUint64(2)
	mem, err := b.u.DirectRead(addr, size)
	b.checkErr(err)
	L.Push(lua.LString(mem))
	return 1
}

func (b *ubind) MemWrite(L *lua.LState) int {
	addr, data := L.CheckUint64(1), L.CheckString(2)
	b.checkErr(b.u.DirectWrite(addr, []byte(data)))
	return 0
}

// lua doesn't have reg enums
func (b *ubind) RegRead(L *lua.LState) int {
	enum := L.CheckInt(1)
	val, err := b.u.RegRead(enum)
	b.checkErr(err)
	L.Push(lua.LNumber(val))
	return 1
}

func (b *ubind) RegWrite(L *lua.LState) int {
	enum, val := L.CheckInt(1), L.CheckUint64(2)
	b.checkErr(b.u.RegWrite(enum, val))
	return 0
}

func (b *ubind) Start(L *lua.LState) int {
	start, end := L.CheckUint64(1), L.CheckUint64(2)
	b.checkErr(b.u.Start(start, end))
	return 0
}

func (b *ubind) Stop(L *lua.LState) int {
	b.checkErr(b.u.Stop())
	return 0
}

// copy-pasted from models/cpu.Cpu
// func (h *Hooks) HookAdd(htype int, cb interface{}, start uint64, end uint64, extra ...int) (Hook, error) {
func (b *ubind) HookAdd(_ *lua.LState) int {
	L := b.L
	htype, fn := L.CheckInt(1), L.CheckFunction(2)
	start := uint64(1)
	end := uint64(0)
	if L.GetTop() >= 4 {
		start, end = L.CheckUint64(3), L.CheckUint64(4)
	}
	luap := lua.P{Fn: fn, NRet: 0, Protect: true}

	var hhptr *lua.LUserData
	var cb interface{}
	switch htype {
	case cpu.HOOK_CODE, cpu.HOOK_BLOCK:
		cb = func(_ cpu.Cpu, addr uint64, size uint32) {
			laddr, lsize := lua.LNumber(addr), lua.LNumber(size)
			// TODO: replace (regs) with a table with a metatable getter/setter
			L.EnvToLua()
			L.SetGlobal("hh", hhptr)
			L.SetGlobal("addr", laddr)
			L.SetGlobal("size", lsize)
			if err := L.CallByParam(luap, laddr, lsize); err != nil {
				fmt.Println(err)
			}
			L.EnvFromLua()
		}
	case cpu.HOOK_INTR:
		cb = func(_ cpu.Cpu, intno uint32) {
			lintno := lua.LNumber(intno)
			L.EnvToLua()
			L.SetGlobal("hh", hhptr)
			L.SetGlobal("intno", lintno)
			if err := L.CallByParam(luap, lintno); err != nil {
				fmt.Println(err)
			}
			L.EnvFromLua()
		}
	case cpu.HOOK_MEM_READ, cpu.HOOK_MEM_WRITE, cpu.HOOK_MEM_READ | cpu.HOOK_MEM_WRITE:
		cb = func(_ cpu.Cpu, access int, addr uint64, size int, val int64) {
			laccess, laddr, lsize, lval := lua.LNumber(access), lua.LNumber(addr), lua.LNumber(size), lua.LNumber(val)
			L.EnvToLua()
			L.SetGlobal("hh", hhptr)
			L.SetGlobal("access", laccess)
			L.SetGlobal("addr", laddr)
			L.SetGlobal("size", lsize)
			L.SetGlobal("val", lval)
			if err := L.CallByParam(luap, laccess, laddr, lsize, lval); err != nil {
				fmt.Println(err)
			}
			L.EnvFromLua()
		}
	case cpu.HOOK_INSN:
		// TODO: allow instruction hooking
		panic("instruction hooking not implemented")
	case cpu.HOOK_MEM_ERR:
		cb = func(_ cpu.Cpu, access int, addr uint64, size int, val int64) bool {
			laccess, laddr, lsize, lval := lua.LNumber(access), lua.LNumber(addr), lua.LNumber(size), lua.LNumber(val)
			L.EnvToLua()
			L.SetGlobal("hh", hhptr)
			L.SetGlobal("access", laccess)
			L.SetGlobal("addr", laddr)
			L.SetGlobal("size", lsize)
			L.SetGlobal("val", lval)
			luap.NRet = 1
			if err := L.CallByParam(luap, lua.LNumber(access), lua.LNumber(addr), lua.LNumber(size), lua.LNumber(val)); err != nil {
				fmt.Println(err)
				return false
			}
			L.EnvFromLua()
			return L.CheckBool(1)
		}
	default:
		L.RaiseError("Unknown hook type: %d", htype)
	}
	hh, err := b.u.HookAdd(htype, cb, start, end)
	b.checkErr(err)

	hhptr = L.NewUserData()
	hhptr.Value = hh
	L.Push(hhptr)
	return 1
}

func (b *ubind) HookDel(L *lua.LState) int {
	hh := L.CheckUserData(1)
	b.u.HookDel(hh.Value.(cpu.Hook))
	return 0
}

func (b *ubind) ContextSave(L *lua.LState) int {
	ctx, err := b.u.ContextSave(nil)
	b.checkErr(err)
	ptr := L.NewUserData()
	ptr.Value = ctx
	L.Push(ptr)
	return 1
}

func (b *ubind) ContextRestore(L *lua.LState) int {
	ptr := L.CheckUserData(1)
	b.u.ContextRestore(ptr.Value)
	return 0
}

func (b *ubind) Close(L *lua.LState) int {
	b.checkErr(b.u.Close())
	return 0
}
