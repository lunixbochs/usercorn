package trace

import (
	"fmt"
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

// TODO: this is duplicated from drcov.go
func WriteEcov(tf *trace.TraceReader, out *os.File) error {
	arch, OS, err := arch.GetArch(tf.Header.Arch, tf.Header.OS)
	if err != nil {
		return errors.Wrap(err, "arch.GetArch() failed")
	}
	config := &models.Config{}
	config.Init()
	replay := trace.NewReplay(arch, OS, tf.Header.CodeOrder, debug.NewDebug(tf.Header.Arch, config))

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
			fmt.Println(errors.Wrap(err, "error reading next trace operation"))
			break
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
					if mod != nil && mod.Prot == 0 {
						fmt.Fprintf(out, "%x\n", o.Addr-mod.Addr)
					}
				case *trace.OpMemMap:
					addmod(o)
				case *trace.OpSyscall:
					for _, op := range o.Ops {
						switch o := op.(type) {
						case *trace.OpMemMap:
							addmod(o)
						}
					}
				}
			}
		}
	}
	replay.Flush()
	return nil
}
