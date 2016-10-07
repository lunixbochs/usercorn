package models

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Output io.WriteCloser

	Color           bool
	ForceBase       uint64
	ForceInterpBase uint64
	LoadPrefix      string
	LoopCollapse    int
	NativeFallback  bool
	SavePost        string
	SavePre         string
	SkipInterp      bool
	Strsize         int
	TraceBlock      bool
	TraceExec       bool
	TraceMatch      []string
	TraceMatchDepth int
	TraceMem        bool
	TraceMemBatch   bool
	TraceReg        bool
	TraceSys        bool
	Verbose         bool

	Demangle bool
	SymFile  bool

	StubSyscalls bool

	PrefixArgs []string
}

func (c *Config) Init() *Config {
	if c == nil {
		return (&Config{}).Init()
	}
	if c.Output == nil {
		c.Output = os.Stderr
	}
	return c
}

func (c *Config) resolveSymlink(path, target string, force bool) string {
	link, err := os.Lstat(path)
	if err == nil && link.Mode()&os.ModeSymlink != 0 {
		if linked, err := os.Readlink(path); err == nil {
			if !filepath.IsAbs(linked) {
				linked = filepath.Join(filepath.Dir(path), linked)
				return c.PrefixPath(linked, false)
			}
			return c.PrefixPath(linked, force)
		}
	}
	exists := !os.IsNotExist(err)
	if force || exists {
		return path
	}
	return target
}

func (c *Config) PrefixPath(path string, force bool) string {
	if c.LoadPrefix == "" {
		return path
	}
	target := path
	if filepath.IsAbs(path) && !strings.HasPrefix(path, c.LoadPrefix) {
		target = filepath.Join(c.LoadPrefix, path)
	}
	return c.resolveSymlink(target, path, force)
}
