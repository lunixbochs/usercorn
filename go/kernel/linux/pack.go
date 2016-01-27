package linux

import (
	"fmt"
	"github.com/lunixbochs/argjoy"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func Pack(buf co.Buf, i interface{}) error {
	switch v := i.(type) {
	case *syscall.Statfs_t:
		fmt.Println("statfs!", v)
	default:
		return argjoy.NoMatch
	}
	return nil
}
