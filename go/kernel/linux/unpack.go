package linux

import (
	"syscall"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux/unpack"
)

func Unpack(buf common.Buf, args []uint64, i interface{}) bool {
	switch v := i.(type) {
	case *syscall.Sockaddr:
		*v = unpack.Sockaddr(buf, int(args[1]))
		return true
	default:
		return false
	}
}
