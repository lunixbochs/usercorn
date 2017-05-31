package ui

import (
	"fmt"
	"github.com/chzyer/readline"
	"github.com/shibukawa/configdir"
	"io"
	"os"
	"path/filepath"

	"github.com/lunixbochs/usercorn/go/lua"
	"github.com/lunixbochs/usercorn/go/models"
)

type Repl struct {
	u   models.Usercorn
	lua *lua.LuaRepl
	rl  *readline.Instance

	multiline bool
	lines     []string
}

type nullCloser struct{ io.Writer }

func (n *nullCloser) Close() error { return nil }

func NewRepl(u models.Usercorn) (*Repl, error) {
	// get history path
	configDirs := configdir.New("usercorn", "repl")
	cacheDir := configDirs.QueryCacheFolder()
	historyPath := ""
	if err := cacheDir.MkdirAll(); err == nil {
		historyPath = filepath.Join(cacheDir.Path, "history")
	}
	rl, err := readline.NewEx(&readline.Config{
		InterruptPrompt: "\n",
		UniqueEditLine:  false,
		HistoryFile:     historyPath,
	})
	if err != nil {
		return nil, err
	}
	luaRepl, err := lua.NewRepl(u, rl.Stderr())
	if err != nil {
		rl.Close()
		return nil, err
	}
	// hijack usercorn output so we can reprint the prompt
	if u.Config().Output == os.Stderr {
		u.Config().Output = &nullCloser{rl.Stderr()}
	}
	return &Repl{u: u, lua: luaRepl, rl: rl}, nil
}

func (r *Repl) Run() {
	go r.runSync()
}

func (r *Repl) OnChange(line []rune, pos int, key rune) (newLine []rune, newPos int, ok bool) {
	rl := r.rl
	if key == '\n' || key == '\r' && !r.multiline {
		rl.Config.UniqueEditLine = true
	} else if key > 0 {
		rl.Config.UniqueEditLine = false
	}
	// returning false keeps readline from messing up the prompt
	return line, pos, false
}

func (r *Repl) setPrompt() {
	u, rl := r.u, r.rl
	pc, _ := u.RegRead(u.Arch().PC)
	rl.SetPrompt(fmt.Sprintf("%#x> ", pc))
	return
	// this is just a demo
	mem, _ := u.DirectRead(pc, 16)
	dis, err := u.Arch().Dis.Dis(mem, pc)
	if err == nil && len(dis) > 0 {
		r.rl.SetPrompt(fmt.Sprintf("[%s %s] ", dis[0].Mnemonic(), dis[0].OpStr()))
	} else {
		r.rl.SetPrompt("> ")
	}
}

func (r *Repl) Reset() {
	r.lines = nil
	r.multiline = false
	r.setPrompt()
}

func (r *Repl) runSync() {
	defer func() {
		r.u.Exit(models.ExitStatus(0))
		r.u.Gate().Unlock()
		r.Close()
	}()

	r.rl.Config.Listener = r
	r.setPrompt()

	defer r.Close()
	for {
		ln := r.rl.Line()
		if ln.Error == readline.ErrInterrupt {
			r.setPrompt()
			r.multiline = false
			r.rl.Config.UniqueEditLine = false
			r.Reset()
			r.u.Stop()
			continue
		} else if ln.CanContinue() {
			continue
		} else if ln.CanBreak() {
			break
		}
		if !r.multiline {
			if ln.Line != "" {
				r.lines = []string{ln.Line}
			}
		} else {
			r.lines = append(r.lines, ln.Line)
		}
		if r.lua.Exec(r.lines) {
			r.rl.Config.UniqueEditLine = false
			r.rl.SetPrompt("... ")
			r.multiline = true
		} else {
			r.multiline = false
			r.setPrompt()
		}
	}
}

func (r *Repl) Close() {
	r.lua.Close()
	r.rl.Close()
}
