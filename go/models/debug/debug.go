package debug

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Debug struct {
	sync.RWMutex
	arch   string
	config *models.Config
	// map of absolute filesystem path to DebugFile
	files map[string]*DebugFile
}

func NewDebug(arch string, config *models.Config) *Debug {
	return &Debug{
		arch:   arch,
		config: config,
		files:  make(map[string]*DebugFile),
	}
}

func (d *Debug) getFile(name string) (*DebugFile, error) {
	tmp, err := filepath.Abs(name)
	if err == nil {
		name = tmp
	}
	d.RLock()
	if df, ok := d.files[name]; ok {
		d.RUnlock()
		return df, nil
	}
	d.RUnlock()
	l, err := loader.LoadFileArch(name, d.arch)
	if err != nil {
		return nil, err
	}
	// TODO: how to surface a non-critical error? u.Log()?
	symbols, _ := l.Symbols()
	DWARF, _ := l.DWARF()
	df := &DebugFile{
		Symbols: symbols,
		DWARF:   DWARF,
	}
	df.CacheSym()
	d.Lock()
	d.files[name] = df
	d.Unlock()
	return df, nil
}

func (d *Debug) File(name string) (*DebugFile, error) {
	// TODO: symlinks probably need to be evaluated in terms of the prefix
	tmp, err := filepath.EvalSymlinks(name)
	if err == nil {
		name = tmp
	}
	// GNU/Linux: try loading /usr/lib/debug version of libraries for debug symbols
	// TODO: only do this on absolute paths?
	debugPath := filepath.Join("/usr/lib/debug", d.config.PrefixRel(name))
	debugPath = d.config.PrefixPath(debugPath, false)
	if _, err := os.Stat(debugPath); err == nil {
		// try a match here
		df, err := d.getFile(debugPath)
		if err == nil {
			return df, nil
		}
	}
	// if no debug library was found, fall back to the original library
	return d.getFile(name)
}

func (d *Debug) Symbolicate(addr uint64, mem cpu.Pages, includeSource bool) (*models.Symbol, string) {
	var (
		filename string
		fileLine string
		sym      models.Symbol
		dist     uint64
	)
	page := mem.Find(addr)
	if page != nil && page.File != nil {
		filename = path.Base(page.File.Name)
		df, _ := d.File(page.File.Name)
		if df != nil {
			sym, dist = df.Symbolicate(addr - page.Addr + page.File.Off)
			if sym.Name == "" {
				// FIXME: we should know if this is PIE or not and adjust how we look up symbols instead of trying both ways
				sym, dist = df.Symbolicate(addr)
			}
			if sym.Name != "" && includeSource {
				if fl := df.FileLine(addr); fl != nil {
					fileLine = fmt.Sprintf("%s:%d", path.Base(fl.File.Name), fl.Line)
				}
			}
		}
	}
	name := sym.Name
	if name != "" {
		if d.config.Demangle {
			name = models.Demangle(name)
		}
		if d.config.SymFile && filename != "" {
			name = fmt.Sprintf("%s@%s", name, filename)
		}
		if dist > 0 {
			name = fmt.Sprintf("%s+0x%x", name, dist)
		}
		if fileLine != "" {
			name = fmt.Sprintf("%s (%s)", name, fileLine)
		}
	}
	return &sym, name
}
