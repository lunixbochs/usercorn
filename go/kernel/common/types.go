package common

import (
	"github.com/lunixbochs/usercorn/go/models"
)

type (
	Buf struct {
		Addr uint64
		U    models.Usercorn
	}
	Obuf struct{ Buf }
	Len  uint64
	Off  int64
	Fd   int32
	Ptr  uint64
)

func NewBuf(u models.Usercorn, addr uint64) Buf {
	return Buf{U: u, Addr: addr}
}

func (b Buf) Struc() *models.StrucStream {
	return b.U.StrucAt(b.Addr)
}

func (b Buf) Pack(i interface{}) error {
	return b.Struc().Pack(i)
}

func (b Buf) Unpack(i interface{}) error {
	return b.Struc().Unpack(i)
}
