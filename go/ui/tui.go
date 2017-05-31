package ui

import (
	"github.com/jroimartin/gocui"
	"github.com/pkg/errors"
	"github.com/shibukawa/configdir"
	"os"
	"path/filepath"
	"strings"

	"github.com/lunixbochs/usercorn/go/lua"
	"github.com/lunixbochs/usercorn/go/models"
)

type Tui struct {
	u   models.Usercorn
	lua *lua.LuaRepl
	g   *gocui.Gui

	histPath  string
	multiline bool
	lines     []string
}

type writerFunc func(p []byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) {
	return w(p)
}

func NewTui(u models.Usercorn) (*Tui, error) {
	luaRepl, err := lua.NewRepl(u, nil)
	if err != nil {
		return nil, errors.Wrap(err, "lua repl failed")
	}
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		luaRepl.Close()
		return nil, errors.Wrap(err, "gocui failed")
	}
	tui := &Tui{
		u:   u,
		lua: luaRepl,
		g:   g,
	}

	// get history path
	configDirs := configdir.New("usercorn", "tui")
	cacheDir := configDirs.QueryCacheFolder()
	if err := cacheDir.MkdirAll(); err == nil {
		tui.histPath = filepath.Join(cacheDir.Path, "history")
	}

	g.SetManagerFunc(tui.layout)
	tui.layout(g)
	tui.bindKeys()
	g.Cursor = true

	// hijack usercorn output
	if u.Config().Output == os.Stderr {
		if v, err := g.View("usercorn"); err == nil {
			u.Config().Output = &nullCloser{v}
		}
	}
	if v, err := g.View("repl"); err == nil {
		luaRepl.SetOutput(writerFunc(func(p []byte) (int, error) {
			for _, b := range p {
				if b == '\n' {
					v.EditNewLine()
				} else {
					v.EditWrite(rune(b))
				}
			}
			return 0, nil
		}))
	}
	return tui, nil
}

func (t *Tui) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (t *Tui) enter(g *gocui.Gui, v *gocui.View) error {
	lines := strings.Split(v.ViewBuffer(), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	v.SetCursor(0, 0)
	v.Clear()
	if !t.lua.Exec(lines) {
	}
	return nil
}

func (t *Tui) bindKeys() error {
	g := t.g
	if err := g.SetKeybinding("", 'q', gocui.ModNone, t.quit); err != nil {
		return err
	}
	if err := g.SetKeybinding("repl", gocui.KeyEnter, gocui.ModNone, t.enter); err != nil {
		return err
	}
	return nil
}

func (t *Tui) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("usercorn", 0, 0, maxX, maxY/2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Editable = false
		v.Wrap = true
	}
	if v, err := g.SetView("repl", 0, maxY/2, maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Editable = true
		v.Wrap = false
		g.SetCurrentView("repl")
	}
	return nil
}

func (t *Tui) Run() {
	go t.runSync()
}

func (t *Tui) Reset() {
	t.lines = nil
	t.multiline = false
}

func (t *Tui) runSync() {
	defer func() {
		t.u.Exit(models.ExitStatus(0))
		t.u.Gate().Unlock()
		t.Close()
	}()
	t.g.MainLoop()
	/*
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
	*/
}

func (t *Tui) Close() {
	t.lua.Close()
	t.g.Close()
}
