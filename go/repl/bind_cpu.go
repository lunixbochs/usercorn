package repl

import (
	"github.com/lunixbochs/usercorn/go/models/cpu"

	"github.com/lunixbochs/luaish"
)

var cpuEnums = map[string]lua.LInt{
	"HOOK_INTR":      cpu.HOOK_INTR,
	"HOOK_INSN":      cpu.HOOK_INSN,
	"HOOK_CODE":      cpu.HOOK_CODE,
	"HOOK_BLOCK":     cpu.HOOK_BLOCK,
	"HOOK_MEM_READ":  cpu.HOOK_MEM_READ,
	"HOOK_MEM_WRITE": cpu.HOOK_MEM_WRITE,
	"HOOK_MEM_ERR":   cpu.HOOK_MEM_ERR,

	"MEM_WRITE_UNMAPPED": cpu.MEM_WRITE_UNMAPPED,
	"MEM_READ_UNMAPPED":  cpu.MEM_READ_UNMAPPED,
	"MEM_FETCH_UNMAPPED": cpu.MEM_FETCH_UNMAPPED,
	"MEM_WRITE_PROT":     cpu.MEM_WRITE_PROT,
	"MEM_READ_PROT":      cpu.MEM_READ_PROT,
	"MEM_FETCH_PROT":     cpu.MEM_FETCH_PROT,

	"MEM_PROT":     cpu.MEM_PROT,
	"MEM_UNMAPPED": cpu.MEM_UNMAPPED,
	"PROT_NONE":    cpu.PROT_NONE,
	"PROT_READ":    cpu.PROT_READ,
	"PROT_WRITE":   cpu.PROT_WRITE,
	"PROT_EXEC":    cpu.PROT_EXEC,
	"PROT_ALL":     cpu.PROT_ALL,

	"MEM_WRITE": cpu.MEM_WRITE,
	"MEM_READ":  cpu.MEM_READ,
	"MEM_FETCH": cpu.MEM_FETCH,
}

// this injects enums from models/cpu
func bindCpu(L *LuaRepl) error {
	mod := L.NewTable()
	for k, v := range cpuEnums {
		mod.RawSetString(k, v)
	}
	L.SetGlobal("cpu", mod)
	return nil
}
