package posix

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
)

type PosixKernel struct {
	common.KernelBase
	Unpack func(common.Buf, interface{})
}
