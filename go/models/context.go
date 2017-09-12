package models

import (
	"fmt"
	"github.com/pkg/errors"
	"strings"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

// like unicorn.ContextSave/Restore, but with memory mappings too

type ContextMem struct {
	Addr, Size uint64
	Prot       int
	Data       []byte
	Desc       string
	File       *cpu.FileDesc
}

type Context struct {
	mem       []*ContextMem
	ctxHandle interface{}
}

func ContextSave(u Usercorn) (*Context, error) {
	var err error
	ctx := &Context{}

	// save regs/cpu state
	ctx.ctxHandle, err = u.ContextSave(nil)
	if err != nil {
		return nil, err
	}

	// save memory mappings
	var errs []string
	for _, m := range u.Mappings() {
		mem, err := u.MemRead(m.Addr, m.Size)
		if err != nil {
			errs = append(errs, fmt.Sprintf("(%s) saving 0x%x-0x%x\n", err, m.Addr, m.Addr+m.Size))
			continue
		}
		ctx.mem = append(ctx.mem, &ContextMem{
			Addr: m.Addr, Size: m.Size, Prot: m.Prot, Data: mem,
			Desc: m.Desc, File: m.File,
		})
	}
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, ", "))
	}
	return ctx, err
}

func ContextRestore(u Usercorn, ctx *Context) error {
	// restore regs/cpu state
	if err := u.ContextRestore(ctx.ctxHandle); err != nil {
		return err
	}
	// unmap all memory
	for _, m := range u.Mappings() {
		u.MemUnmap(m.Addr, m.Size)
	}
	// restore saved memory
	for _, m := range ctx.mem {
		u.MemMap(m.Addr, m.Size, m.Prot)
		u.MemWrite(m.Addr, m.Data)
		// TODO: this could have a bug if the saved mapping overlapped with an existing mapping somehow
		x := u.Mappings()
		x[len(x)-1].Desc = m.Desc
		x[len(x)-1].File = m.File
	}
	return nil
}
