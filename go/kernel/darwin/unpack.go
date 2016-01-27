package darwin

import (
	"github.com/lunixbochs/argjoy"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func Unpack(k co.Kernel, arg interface{}, vals []interface{}) error {
	return argjoy.NoMatch
}

func registerUnpack(d *DarwinKernel) {
	d.Argjoy.Register(func(arg interface{}, vals []interface{}) error {
		return Unpack(d, arg, vals)
	})
}
