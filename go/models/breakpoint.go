package models

import (
	"fmt"
	"github.com/pkg/errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"regexp"
	"strconv"
)

var breakRe = regexp.MustCompile(`^((?P<addr>\*?0x[0-9a-fA-F]+|\d+)|(?P<source>.+):(?P<line>\d+)|(?P<sym>.+?(?P<off>\+0x[0-9a-fA-F]+|\d+)?))(@(?P<file>.+))?$`)

type Breakpoint struct {
	// break at address
	Addr uint64

	// symbol and offset
	Sym string
	Off uint64

	// source file and line
	Source string
	Line   uint64

	// binary filename
	Filename string

	// list of active addresses
	hooks []bpHook

	u  Usercorn
	cb func(u Usercorn, addr uint64)
}

type bpHook struct {
	addr uint64
	hook uc.Hook
}

var BreakpointParseErr = fmt.Errorf("breakpoint parse failed")

// desc can be (0xADDR, sym, sym+0xOFF, sym+0xOFF, or sourcefile:line, can suffix with @file to restrict to a single library/mapped file)
// "future" controls whether breakpoint will be applied to every candidate location in the future, or just the ones currently existing
func NewBreakpoint(desc string, cb func(u Usercorn, addr uint64), u Usercorn) (*Breakpoint, error) {
	r := breakRe.FindStringSubmatch(desc)
	if len(r) == 0 {
		return nil, errors.WithStack(BreakpointParseErr)
	}
	addrG, sourceG, lineG, sym, offG, fileG := r[2], r[3], r[4], r[5], r[6], r[8]
	var (
		addr   uint64
		off    uint64
		source string
		line   uint64
	)
	var err error
	if addrG != "" {
		addr, err = strconv.ParseUint(addrG, 0, 64)
	} else if sym != "" && offG != "" {
		off, err = strconv.ParseUint(offG, 0, 64)
	} else if sourceG != "" && lineG != "" {
		line, err = strconv.ParseUint(lineG, 0, 64)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse int")
	}
	b := &Breakpoint{
		Addr:     addr,
		Sym:      sym,
		Off:      off,
		Source:   source,
		Line:     line,
		Filename: fileG,

		u:  u,
		cb: cb,
	}
	return b, nil
}

// installs a breakpoint to all matching addresses in b.u
func (b *Breakpoint) Apply() error {
	var addrs []uint64

	// addr implicitly used if no sym or source file are set- to allow a breakpoint at 0x0 without a separate attr
	if b.Sym == "" && b.Source == "" {
		// TODO: this ignores @file, do we care?
		addrs = append(addrs, b.Addr)
	} else {
		for _, f := range b.u.MappedFiles() {
			if b.Filename == "" || f.Name == b.Filename {
				if b.Sym != "" {
					sym := f.SymbolLookup(b.Sym)
					if sym.Name == b.Sym {
						addrs = append(addrs, sym.Start+b.Off)
					}
				} else if b.Source != "" {
					// TODO: we need an inverse of MappedFile.FileLine() for this
					panic("not implemented")
				}
			}
		}
	}
	if len(addrs) == 0 {
		return errors.Errorf("no breakpoints set")
	}
outer:
	for _, addr := range addrs {
		for _, already := range b.hooks {
			if already.addr == addr {
				continue outer
			}
		}
		hook, err := b.u.HookAdd(uc.HOOK_CODE, func(_ uc.Unicorn, addr uint64, size uint32) {
			b.cb(b.u, addr)
		}, addr, addr+1)
		if err != nil {
			return errors.Wrap(err, "u.HookAdd() failed")
		}
		b.hooks = append(b.hooks, bpHook{addr, hook})
	}
	return nil
}

// removes all Unicorn hooks added by this breakpoint
func (b *Breakpoint) Remove() error {
	for _, hook := range b.hooks {
		b.u.HookDel(hook.hook)
	}
	b.hooks = nil
	return nil
}
