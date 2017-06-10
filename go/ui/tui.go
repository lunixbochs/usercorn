package ui

import (
	"github.com/chzyer/readline"
	"github.com/jroimartin/gocui"
	"github.com/lunixbochs/vtclean"
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
	rl  *readline.Instance

	input     *fifoReader
	histPath  string
	multiline bool
	lines     []string
}

type tailWriter struct {
	*gocui.View
	line string
}

func (t *tailWriter) Write(p []byte) (int, error) {
	// Literally just write spaces over the current line D:
	x, y := t.Cursor()
	t.Overwrite = true
	t.SetCursor(0, y)
	for i := 0; i < x; i++ {
		t.EditWrite(' ')
	}
	t.SetCursor(0, y)
	t.Overwrite = false

	// Clean out terminal codes
	t.line = t.line + string(p)
	t.line = vtclean.Clean(t.line, false)

	for _, c := range t.line {
		if c == '\n' {
			t.EditNewLine()
			t.line = ""
			y += 1
		} else {
			t.EditWrite(c)
		}
	}
	t.SetCursor(len(t.line), y)
	return 0, nil
}

type fifoReader struct {
	c   chan []byte
	buf []byte
}

func (f *fifoReader) Read(p []byte) (int, error) {
	f.buf = append(f.buf, <-f.c...)
outer:
	for {
		select {
		case d := <-f.c:
			f.buf = append(f.buf, d...)
			// fill buf as much as we can
		default:
			// do nothing
			break outer
		}
	}
	// Empty buf into p?
	n := copy(p, f.buf)
	// Truncate front n
	copy(f.buf, f.buf[n:])
	f.buf = f.buf[:len(f.buf)-n]
	return n, nil
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
		u:     u,
		lua:   luaRepl,
		g:     g,
		input: &fifoReader{c: make(chan []byte)},
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
			u.Config().Output = &nullCloser{&tailWriter{View: v}}
		}
	}
	if v, err := g.View("repl"); err == nil {
		v.Editor = gocui.EditorFunc(tui.replInput)
		rl, err := readline.NewEx(&readline.Config{
			InterruptPrompt: "\n",
			UniqueEditLine:  false,
			Stdin:           tui.input,
			Stdout:          &tailWriter{View: v},
			Stderr:          &tailWriter{View: v},
		})
		if err != nil {
			return nil, err
		}
		tui.rl = rl
		luaRepl.SetOutput(rl.Stdout())
	}

	return tui, nil
}

func (t *Tui) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (t *Tui) replInput(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	switch {
	case key > 0 && key <= 127:
		t.input.c <- []byte{byte(key)}
	case ch > 0 && ch <= 127:
		t.input.c <- []byte{byte(ch)}
	}
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
	go func() {
		t.rl.SetPrompt("> ")
		for {
			ln := t.rl.Line()
			if ln.Error == readline.ErrInterrupt {
				t.rl.SetPrompt("> ")
				t.multiline = false
				t.rl.Config.UniqueEditLine = false
				t.Reset()
				t.u.Stop()
				continue
			} else if ln.CanContinue() {
				continue
			} else if ln.CanBreak() {
				break
			}
			if !t.multiline {
				if ln.Line != "" {
					t.lines = []string{ln.Line}
				}
			} else {
				t.lines = append(t.lines, ln.Line)
			}
			if t.lua.Exec(t.lines) {
				t.rl.Config.UniqueEditLine = false
				t.rl.SetPrompt("... ")
				t.multiline = true
			} else {
				t.multiline = false
				t.rl.SetPrompt("> ")
			}
		}

	}()
	t.g.MainLoop()
}

func (t *Tui) Close() {
	t.lua.Close()
	t.g.Close()
}
