package common

import (
	"github.com/lunixbochs/usercorn/go/models"
)

type (
	Buf struct {
		Addr uint64
		U    models.Usercorn
		*models.StrucStream
	}
	Obuf Buf
	Len  uint64
	Off  int64
	Fd   int32
	Ptr  uint64
)

func NewBuf(u models.Usercorn, addr uint64) Buf {
	return Buf{U: u, Addr: addr, StrucStream: u.StrucAt(addr)}
}

func (b Buf) Copy() Buf {
	return NewBuf(b.U, b.Addr)
}
