package linux

import (
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux/unpack"
)

func Unpack(buf co.Buf, args []uint64, i interface{}) error {
	switch v := i.(type) {
	case *syscall.Sockaddr:
		*v = unpack.Sockaddr(buf, int(args[1]))
		return nil
	default:
		return co.UnknownUnpackType
	}
}
