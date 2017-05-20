package repl

import (
	"fmt"
	"github.com/chzyer/readline"
	"github.com/lunixbochs/luaish"
	"github.com/lunixbochs/luaish/parse"
	"io"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

type LuaRepl struct {
	*lua.LState
	u  models.Usercorn
	rl *readline.Instance

	Multiline bool
	lines     []string
	last      []string
	lastCmd   string

	preRegs []models.RegVal
}

// TODO: eventually support multiple usercorn instances in a repl
func NewLuaRepl(u models.Usercorn, rl *readline.Instance) *LuaRepl {
	repl := &LuaRepl{
		LState: lua.NewState(),

		rl: rl,
		u:  u,
	}
	if err := repl.loadBindings(); err != nil {
		panic("failed to load repl bindings: " + err.Error())
	}
	return repl
}

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
			val := lua.LNumber(r.Val)
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

func (L *LuaRepl) EnvFromLua() {
	// read register values back out
	// TODO: what about psuedo-registers?
	// TODO: gah, what if lua steps so the registers change under us?

	u := L.u
	vals, _ := u.RegDump()
	for i, r := range vals {
		v := L.GetGlobal(r.Name)
		if val, ok := v.(lua.LNumber); !ok {
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
	// print returned values
	// TODO: make _fallback() just add values to a queue, or call the same host printer?

	// if exactly one value was returned, and it's a function, call it with no args
	if len(lv) == 1 && lv[0].Type() == lua.LTFunction {
		L.Push(lv[0])
		if lv2, err := L.Call(lv[0].(*lua.LFunction)); err != nil {
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
	code := strings.Join(L.lines, "\n")
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

func (L *LuaRepl) Reset() {
	L.lines = nil
	L.last = nil
	L.lastCmd = ""
}

func (L *LuaRepl) Feed(line string) bool {
	if len(L.lines) == 0 && line == "" {
		if len(L.last) > 0 {
			L.lines = L.last
		} else {
			return false
		}
	} else {
		L.lines = append(L.lines, line)
	}
	fn, err, incomplete := L.loadstring(L.lines, true)
	if incomplete {
		L.last = nil
		return true
	}
	L.last = L.lines
	L.lastCmd = strings.TrimSpace(strings.Join(L.lines, " "))
	L.lines = nil
	if err != nil {
		L.Println(err)
	} else {
		L.preRun()
		lv, err := L.Call(fn)
		if err != nil {
			L.Println(err)
		}
		L.postRun(lv)
	}
	return false
}

func (L *LuaRepl) getArgs() []lua.LValue {
	lv := make([]lua.LValue, L.GetTop())
	for i := range lv {
		lv[i] = L.CheckAny(i + 1)
	}
	return lv
}

// runs a loaded lua function, returning any errors or return values
func (L *LuaRepl) Call(fn *lua.LFunction) ([]lua.LValue, error) {
	L.SetTop(0)
	L.Push(fn)
	if err := L.PCall(0, lua.MultRet, nil); err != nil {
		return nil, err
	}
	return L.getArgs(), nil
}

// This is a readline Listener, triggered on keypress.
// The original function is to erase the prompt if you press enter without typing.
func (L *LuaRepl) OnChange(line []rune, pos int, key rune) (newLine []rune, newPos int, ok bool) {
	rl := L.rl
	if key == '\n' || key == '\r' && !L.Multiline {
		rl.Config.UniqueEditLine = true
	} else if key > 0 {
		rl.Config.UniqueEditLine = false
	}
	// returning false keeps readline from messing up the prompt
	return line, pos, false
}

func (L *LuaRepl) Printf(f string, arg ...interface{}) {
	fmt.Fprintf(L.rl, f, arg...)
}

func (L *LuaRepl) Println(arg ...interface{}) {
	fmt.Fprintln(L.rl, arg...)
}

var cleanup []func()

type NullCloser struct {
	io.Writer
}

func (n *NullCloser) Close() error { return nil }

func Run(u models.Usercorn) error {
	u.Gate().Lock()
	rl, err := readline.NewEx(&readline.Config{
		InterruptPrompt: "\n",
		UniqueEditLine:  false,
	})
	if err != nil {
		return err
	}
	u.Config().Output = &NullCloser{rl.Stderr()}

	cleanup = append(cleanup, func() { rl.Close() })
	go func() {
		defer func() {
			u.Exit(models.ExitStatus(0))
			u.Gate().Unlock()
			rl.Close()
		}()

		repl := NewLuaRepl(u, rl)
		rl.Config.Listener = repl

		setPrompt := func() {
			pc, _ := u.RegRead(u.Arch().PC)
			rl.SetPrompt(fmt.Sprintf("%#x> ", pc))
			return
			// this is just a demo
			mem, _ := u.DirectRead(pc, 16)
			dis, err := u.Arch().Dis.Dis(mem, pc)
			if err == nil && len(dis) > 0 {
				rl.SetPrompt(fmt.Sprintf("[%s %s] ", dis[0].Mnemonic(), dis[0].OpStr()))
			} else {
				rl.SetPrompt("> ")
			}
		}
		setPrompt()

		defer repl.Close()
		for {
			ln := rl.Line()
			if ln.Error == readline.ErrInterrupt {
				setPrompt()
				repl.Multiline = false
				rl.Config.UniqueEditLine = false
				repl.Reset()
				u.Stop()
				continue
			} else if ln.CanContinue() {
				continue
			} else if ln.CanBreak() {
				break
			}
			if repl.Feed(ln.Line) {
				rl.Config.UniqueEditLine = false
				rl.SetPrompt("... ")
				repl.Multiline = true
			} else {
				repl.Multiline = false
				setPrompt()
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
