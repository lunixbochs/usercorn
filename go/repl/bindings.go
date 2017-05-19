package repl

import (
	"github.com/lunixbochs/luaish"
)

func (L *LuaRepl) printFunc(_ *lua.LState) int {
	L.PrettyPrint(L.getArgs(), false)
	return 0
}

func (L *LuaRepl) loadBindings() error {
	print := L.NewFunction(L.printFunc)
	L.SetGlobal("print", print)

	if err := bindCpu(L); err != nil {
		return err
	} else if err := bindUsercorn(L); err != nil {
		return err
	} else if err := L.DoString(sugarRc); err != nil {
		return err
	} else if err := L.DoString(cmdRc); err != nil {
		return err
	}
	return nil
}
