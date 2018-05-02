package trace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
	"io"
	"os"
	"sort"

	"github.com/lunixbochs/usercorn/go/arch"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
	"github.com/lunixbochs/usercorn/go/models/debug"
	"github.com/lunixbochs/usercorn/go/models/trace"
)

type drcovBB struct {
	Start uint32
	Size  uint16
	ModId uint16
}

var strucOptions = &struc.Options{Order: binary.LittleEndian}

func WriteDrcov(tf *trace.TraceReader, out *os.File) error {
	arch, OS, err := arch.GetArch(tf.Header.Arch, tf.Header.OS)
	if err != nil {
		return errors.Wrap(err, "arch.GetArch() failed")
	}
	config := &models.Config{}
	config.Init()
	replay := trace.NewReplay(arch, OS, tf.Header.CodeOrder, debug.NewDebug(tf.Header.Arch, config))

	var blocks bytes.Buffer
	bbCount := 0
	modserial := 0
	modules := make(map[string]*cpu.Page)
	modlookup := make(cpu.Pages, 0)

	addmod := func(o *trace.OpMemMap) {
		if o.Prot&cpu.PROT_EXEC == 0 {
			return
		}
		key := o.Desc + "|" + o.File
		if _, ok := modules[key]; !ok {
			desc := o.File
			if desc == "" {
				desc = "[" + o.Desc + "]"
			}
			mod := &cpu.Page{Addr: o.Addr, Size: o.Size, Prot: modserial, Desc: desc}
			modules[key] = mod
			modlookup = append(modlookup, mod)
			modserial++
		}
		sort.Sort(modlookup)
	}

	for {
		op, err := tf.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return errors.Wrap(err, "error reading next trace operation")
		}
		switch frame := op.(type) {
		case *trace.OpKeyframe:
			for _, op := range frame.Ops {
				switch o := op.(type) {
				case *trace.OpMemMap:
					addmod(o)
				}
			}
		case *trace.OpFrame:
			for _, op := range frame.Ops {
				switch o := op.(type) {
				case *trace.OpJmp:
					mod := modlookup.Find(o.Addr)
					bb := drcovBB{
						Start: uint32(o.Addr - mod.Addr),
						Size:  uint16(o.Size),
						ModId: uint16(mod.Prot),
					}
					struc.PackWithOptions(&blocks, &bb, strucOptions)
					bbCount++
				case *trace.OpMemMap:
					addmod(o)
				}
			}
		}
	}
	replay.Flush()

	// write output file
	fmt.Fprintf(out, "DRCOV VERSION: 2\n")
	fmt.Fprintf(out, "DRCOV FLAVOR: drcov-64\n")
	fmt.Fprintf(out, "Module Table: version 2, count %d\n", len(modules))
	fmt.Fprintf(out, "Columns: id, base, end, entry, path\n")
	for _, page := range modules {
		fmt.Fprintf(out, "%d, %#016x, %#016x, %#016x, %s\n", page.Prot, page.Addr, page.Addr+page.Size, 0, page.Desc)
	}
	fmt.Fprintf(out, "BB Table: %d bbs\n", bbCount)
	if _, err := blocks.WriteTo(out); err != nil {
		return err
	}
	return nil
}
