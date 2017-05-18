package repl

func (L *LuaRepl) loadBindings() error {
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
