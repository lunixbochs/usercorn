package linux

import (
	"github.com/lunixbochs/argjoy"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux/unpack"
	"github.com/lunixbochs/usercorn/go/native"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

func Unpack(k *LinuxKernel, arg interface{}, vals []interface{}) error {
	reg0 := vals[0].(uint64)
	// null pointer guard
	if reg0 == 0 {
		return nil
	}
	buf := co.NewBuf(k, reg0)
	switch v := arg.(type) {
	case *syscall.Sockaddr:
		*v = unpack.Sockaddr(buf, int(vals[1].(uint64)))
	case **native.Fdset32:
		tmp := &native.Fdset32{}
		if err := buf.Unpack(tmp); err != nil {
			return err
		}
		*v = tmp
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

func registerUnpack(k *LinuxKernel) {
	k.Argjoy.Register(func(arg interface{}, vals []interface{}) error {
		return Unpack(k, arg, vals)
	})
}
