package repl

import (
	"fmt"
	"github.com/chzyer/readline"
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/luaish/parse"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

type LuaRepl struct {
	*lua.LState
	u models.Usercorn

	lines []string
}

// TODO: eventually support multiple usercorn instances in a repl
func NewLuaRepl(u models.Usercorn) *LuaRepl {
	repl := &LuaRepl{
		LState: lua.NewState(), u: u,
	}
	if err := repl.loadBindings(); err != nil {
		panic("failed to load repl bindings: " + err.Error())
	}
	return repl
}

func (L *LuaRepl) preRun() {
	u := L.u
	vals, err := u.RegDump()
	if err != nil {
		fmt.Printf("error in u.RegDump(): %v\n", err)
	} else {
		// write reg values
		// TODO: what about psuedo / partial registers?
		for _, r := range vals {
			val := lua.LNumber(r.Val)
			L.SetGlobal(r.Name, val)
			if r.Enum == u.Arch().PC {
				L.SetGlobal("pc", val)
			} else if r.Enum == u.Arch().SP {
				L.SetGlobal("sp", val)
			}
		}
	}
}

func (L *LuaRepl) postRun(lv []lua.LValue) {
	// print returned values
	// TODO: make _fallback() just add values to a queue, or call the same host printer?
	if len(lv) > 0 && !(len(lv) == 1 && lv[0] == lua.LNil) {
		pretty := make([]string, len(lv))
		for i, v := range lv {
			switch s := v.(type) {
			case lua.LString:
				// for some reason repr doesn't print out null bytes properly
				// pretty[i] = models.Repr([]byte(s), 0)
				pretty[i] = fmt.Sprintf("%#v", s)
			default:
				pretty[i] = v.String()
			}
		}
		fmt.Printf("%s\n", strings.Join(pretty, " "))
	}
	// read register values back out
	// TODO: what about psuedo-registers?
	u := L.u
	vals, _ := u.RegDump()
	for _, r := range vals {
		v := L.GetGlobal(r.Name)
		if val, ok := v.(lua.LNumber); !ok {
			fmt.Printf("could not restore %s: bad type: %v\n", r.Name, v)
		} else if uint64(val) != r.Val {
			u.RegWrite(r.Enum, uint64(val))
		}
	}
}

func (L *LuaRepl) loadstring(code string) (*lua.LFunction, error, bool) {
	if fn, err := L.LoadString(code); err != nil {
		// check for incomplete parse
		if lerr, ok := err.(*lua.ApiError); ok {
			if perr, ok := lerr.Cause.(*parse.Error); ok {
				if perr.Pos.Line == parse.EOF {
					return nil, err, true
				} else {
					// still a parse error: try injecting return
					if !strings.HasPrefix(code, "return ") {
						return L.loadstring("return " + code)
					}
				}
			}
		}
		return nil, err, false
	} else {
		return fn, nil, false
	}
}

func (L *LuaRepl) Feed(line string) bool {
	L.lines = append(L.lines, line)

	if fn, err, incomplete := L.loadstring(strings.Join(L.lines, " ")); incomplete {
		return true
	} else if err != nil {
		fmt.Println(err)
	} else {
		L.lines = L.lines[:0]
		L.preRun()
		lv, err := L.Run(fn)
		if err != nil {
			fmt.Println(err)
		}
		L.postRun(lv)
	}
	return false
}

// runs a loaded lua function, returning any errors or return values
func (L *LuaRepl) Run(fn *lua.LFunction) ([]lua.LValue, error) {
	top := L.GetTop()
	L.Push(fn)
	if err := L.PCall(0, lua.MultRet, nil); err != nil {
		return nil, err
	}
	count := L.GetTop() - top
	ret := make([]lua.LValue, count)
	for i := 0; i < count; i++ {
		ret[i] = L.Get(top + i + 1)
	}
	return ret, nil
}

var cleanup []func()

func Run(u models.Usercorn) error {
	u.Gate().Lock()
	rl, err := readline.NewEx(&readline.Config{})
	if err != nil {
		return err
	}
	cleanup = append(cleanup, func() { rl.Close() })
	go func() {
		defer func() {
			u.Exit(models.ExitStatus(0))
			u.Gate().Unlock()
			rl.Close()
		}()

		rl.SetPrompt("> ")
		repl := NewLuaRepl(u)
		defer repl.Close()
		for {
			ln := rl.Line()
			if ln.CanContinue() {
				continue
			} else if ln.CanBreak() {
				break
			}
			if repl.Feed(ln.Line) {
				rl.SetPrompt("... ")
			} else {
				rl.SetPrompt("> ")
			}
		}
	}()
	return nil
}

func Exit() {
	for _, f := range cleanup {
		f()
	}
}
