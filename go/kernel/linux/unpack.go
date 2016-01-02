package linux

import (
	"github.com/lunixbochs/argjoy"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux/unpack"
	"github.com/lunixbochs/usercorn/go/native"
)

func (k *LinuxKernel) Unpack(arg interface{}, vals []interface{}) error {
	buf := co.NewBuf(k.U, vals[0].(uint64))
	// null pointer guard
	if buf.Addr == 0 {
		return nil
	}
	switch v := arg.(type) {
	case *syscall.Sockaddr:
		*v = unpack.Sockaddr(buf, int(vals[1].(uint64)))
		return nil
	case **native.Fdset32:
		tmp := &native.Fdset32{}
		if err := buf.Unpack(tmp); err != nil {
			return err
		}
		*v = tmp
		return nil
	default:
		return argjoy.NoMatch
	}
}
