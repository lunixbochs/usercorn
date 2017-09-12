package debug

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
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
