package darwin

import (
	"github.com/lunixbochs/argjoy"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/darwin/unpack"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

func Unpack(k co.Kernel, arg interface{}, vals []interface{}) error {
	// TODO: this is the exact same preamble as linux
	reg0 := vals[0].(uint64)
	// null pointer guard
	if reg0 == 0 {
		return nil
	}
	switch v := arg.(type) {
	case *enum.OpenFlag:
		*v = unpack.OpenFlag(reg0)
	case *enum.MmapFlag:
		*v = unpack.MmapFlag(reg0)
	case *enum.MmapProt:
		*v = unpack.MmapProt(reg0)
	default:
		return argjoy.NoMatch
	}
	return nil
}

func registerUnpack(d *DarwinKernel) {
	d.Argjoy.Register(func(arg interface{}, vals []interface{}) error {
		return Unpack(d, arg, vals)
	})
}
