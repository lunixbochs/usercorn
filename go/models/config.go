package models

import (
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Color           bool
	Demangle        bool
	ForceBase       uint64
	ForceInterpBase uint64
	LoadPrefix      string
	LoopCollapse    int
	TraceExec       bool
	TraceMatch      []string
	TraceMatchDepth int
	TraceMem        bool
	TraceMemBatch   bool
	TraceReg        bool
	TraceSys        bool
	Verbose         bool
	Strsize         int

	PrefixArgs []string
}

func (c *Config) resolveSymlink(path, target string, force bool) string {
	link, err := os.Lstat(path)
	if err == nil && link.Mode()&os.ModeSymlink != 0 {
		if linked, err := os.Readlink(path); err != nil {
			if !strings.HasPrefix(linked, "/") {
				linked = filepath.Join(filepath.Dir(path), linked)
				return c.PrefixPath(path, false)
			}
			return c.PrefixPath(linked, force)
		}
	}
	exists := !os.IsNotExist(err)
	if force || exists {
		return target
	}
	return path
}

func (c *Config) PrefixPath(path string, force bool) string {
	if c.LoadPrefix == "" {
		return path
	}
	target := path
	if filepath.IsAbs(path) {
		target = filepath.Join(c.LoadPrefix, path)
	}
	return c.resolveSymlink(path, target, force)
}
