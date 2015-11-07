package posix

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

func Uname(buf co.Buf, un *models.Uname) {
	buf.Pack(un)
}
