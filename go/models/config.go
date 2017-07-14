package models

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

type TraceConfig struct {
	Tracefile   string
	TraceWriter io.WriteCloser

	Everything bool // enables all other flags
	// TODO: what about only tracing specific address ranges?
	Block      bool // implied by Ins
	Ins        bool
	Mem        bool
	Reg        bool
	SpecialReg bool
	Sys        bool

	OpCallback []func(Op)

	// Filters
	LoopCollapse int
	// TODO: Maybe CollapseSideeffect
	// (Collapse a basic block's side effects into a single one)
	MemBatch   bool
	Match      []string
	MatchDepth int
}

func (t *TraceConfig) Any() bool {
	return t.Everything || t.Block || t.Ins || t.Mem || t.SpecialReg || t.Sys
}

func (t *TraceConfig) Init() {
	if t.Ins {
		t.Block = true
	}
	// mtrace is required as the UI doesn't have access to main memory anymore
	if t.Ins || t.Block {
		t.Mem = true
	}
	if t.Everything {
		t.Block = true
		t.Ins = true
		t.Mem = true
		t.Reg = true
		t.SpecialReg = true
		t.Sys = true
	}
}

type Config struct {
	Output io.WriteCloser

	Env  []string
	Args []string

	Color           bool
	ForceBase       uint64
	ForceInterpBase uint64
	LoadPrefix      string
	NativeFallback  bool
	SkipInterp      bool
	Strsize         int
	Verbose         bool

	Trace  TraceConfig
	Rewind bool
	UI     bool

	SymFile bool

	BlockSyscalls bool
	StubSyscalls  bool
	InsCount      bool

	PrefixArgs []string

	// TODO: UI sub config
	Demangle bool
	DisBytes bool

	// TODO: Maybe add option to load whole binary into trace
	// (For replay and such).
	SourcePaths []string
	TraceSource bool
}

func (c *Config) Init() *Config {
	if c == nil {
		return (&Config{}).Init()
	}
	if c.Output == nil {
		c.Output = os.Stderr
	}
	c.Trace.Init()
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

func (c *Config) PrefixRel(path string) string {
	// returns an absolute path inside the load prefix
	// as a path relative to the prefix base
	if !filepath.IsAbs(path) {
		return path
	}
	rel, err := filepath.Rel(c.LoadPrefix, path)
	if err != nil {
		return path
	}
	split := filepath.SplitList(rel)
	if len(split) > 0 && split[0] == ".." {
		return path
	}
	return rel
}
