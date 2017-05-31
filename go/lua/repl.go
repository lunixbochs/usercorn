package lua

import (
	"fmt"
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/luaish/parse"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	"io"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

type LuaRepl struct {
	*lua.LState
	u models.Usercorn
	io.Writer

	preRegs []models.RegVal
}

// TODO: eventually support multiple usercorn instances in a repl

// Return a new lua repl bound to a Usercorn instance.
func NewRepl(u models.Usercorn, o io.Writer) (*LuaRepl, error) {
	repl := &LuaRepl{
		LState: lua.NewState(),
		u:      u,
		Writer: o,
	}
	if err := repl.loadBindings(); err != nil {
		return nil, errors.Wrap(err, "failed to load repl bindings")
	}
	configDirs := configdir.New("usercorn", "lua")
	for _, config := range configDirs.QueryFolders(configdir.All) {
		config.MkdirAll()
		if data, err := config.ReadFile("init.lish"); err == nil {
			if err := repl.DoString(string(data)); err != nil {
				repl.Printf("error while reading init.lish: %v\n", err)
			}
		}
	}
	return repl, nil
}

func (l *LuaRepl) SetOutput(w io.Writer) {
	l.Writer = w
}

// Writes emulator state to lua globals.
func (L *LuaRepl) EnvToLua() {
	u := L.u
	vals, err := u.RegDump()
	if err != nil {
		L.Printf("error in u.RegDump(): %v\n", err)
	} else {
		L.preRegs = vals
		// write reg values
		// TODO: what about psuedo / partial registers?
		for _, r := range vals {
			val := lua.LInt(r.Val)
			L.SetGlobal(r.Name, val)
			if r.Enum == u.Arch().PC {
				L.SetGlobal("pc", val)
			} else if r.Enum == u.Arch().SP {
				L.SetGlobal("sp", val)
			}
		}
	}
	pc, _ := u.RegRead(u.Arch().PC)
	mem, _ := u.DirectRead(pc, 16)
	if u.Arch().Dis != nil {
		dis, err := u.Arch().Dis.Dis(mem, pc)
		if err == nil && len(dis) > 0 {
			ins := disToLua(L, dis[:1])[0]
			L.SetGlobal("ins", ins)
			L.SetGlobal("ops", ins.RawGetString("ops"))
		}
	}
}

// Restores emulator state from lua globals.
func (L *LuaRepl) EnvFromLua() {
	// TODO: what about psuedo-registers?
	u := L.u
	vals, _ := u.RegDump()
	for i, r := range vals {
		v := L.GetGlobal(r.Name)
		if val, ok := v.(lua.LInt); !ok {
			L.Printf("could not restore %s: bad type: %v\n", r.Name, v)
		} else if uint64(val) != L.preRegs[i].Val {
			u.RegWrite(r.Enum, uint64(val))
		}
	}
}

func (L *LuaRepl) preRun() {
	L.EnvToLua()
}

func (L *LuaRepl) postRun(lv []lua.LValue) {
	// TODO: make _fallback() just add values to a queue, or call the same host printer?

	// if exactly one value was returned, and it's a function, call it with no args
	if len(lv) == 1 && lv[0].Type() == lua.LTFunction {
		L.Push(lv[0])
		if lv2, err := L.call(lv[0].(*lua.LFunction)); err != nil {
			L.Println(err)
			lv = nil
		} else {
			lv = lv2
		}
	}

	// ignore len(1) if nil, otherwise print all values
	if len(lv) == 1 && lv[0] == lua.LNil {
	} else if len(lv) > 0 {
		L.PrettyPrint(lv, true)
	}

	// set the _ global
	if len(lv) == 1 {
		L.SetGlobal("_", lv[0])
	} else if len(lv) > 1 {
		tmp := L.NewTable()
		for i, v := range lv {
			L.RawSetInt(tmp, i+1, v)
		}
		L.SetGlobal("_", tmp)
	} else {
		L.SetGlobal("_", lua.LNil)
	}
	L.EnvFromLua()
}

func (L *LuaRepl) loadstring(lines []string, recurse bool) (*lua.LFunction, error, bool) {
	code := strings.Join(lines, "\n")
	if len(lines) == 1 && recurse {
		code = "return " + code
	}
	if fn, err := L.LoadString(code); err != nil {
		// check for incomplete parse
		if lerr, ok := err.(*lua.ApiError); ok {
			if perr, ok := lerr.Cause.(*parse.Error); ok {
				if perr.Pos.Line == parse.EOF {
					return nil, err, true
				} else if recurse {
					// still a parse error: try without return
					return L.loadstring(lines, false)
				}
			}
		}
		return nil, err, false
	} else {
		return fn, nil, false
	}
}

// Runs a multiline script, returning true if more input is needed.
// Errors will be printed.
func (L *LuaRepl) Exec(lines []string) bool {
	if len(lines) == 0 {
		return true
	}
	fn, err, incomplete := L.loadstring(lines, true)
	if incomplete {
		return true
	}
	if err != nil {
		L.Println(err)
	} else {
		L.preRun()
		lv, err := L.call(fn)
		if err != nil {
			L.Println(err)
		}
		L.postRun(lv)
	}
	return false
}

// Returns a list of lua.LValue for each value on the stack.
func (L *LuaRepl) getArgs() []lua.LValue {
	lv := make([]lua.LValue, L.GetTop())
	for i := range lv {
		lv[i] = L.CheckAny(i + 1)
	}
	return lv
}

// Runs a loaded lua function, returning any errors or return values
func (L *LuaRepl) call(fn *lua.LFunction) ([]lua.LValue, error) {
	L.SetTop(0)
	L.Push(fn)
	if err := L.PCall(0, lua.MultRet, nil); err != nil {
		return nil, err
	}
	return L.getArgs(), nil
}

// A Printf() wrapper around the repl's output.
func (L *LuaRepl) Printf(f string, arg ...interface{}) {
	fmt.Fprintf(L, f, arg...)
}

// A Println() wrapper around the repl's output.
func (L *LuaRepl) Println(arg ...interface{}) {
	fmt.Fprintln(L, arg...)
}
