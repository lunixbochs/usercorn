package common

import (
	"reflect"

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
	Fd   int
	Ptr  uint64
)

func NewBuf(u models.Usercorn, addr uint64) Buf {
	return Buf{U: u, Addr: addr, StrucStream: u.StrucAt(addr)}
}

func (b Buf) Copy() Buf {
	return NewBuf(b.U, b.Addr)
}

var (
	BufType  = reflect.TypeOf(Buf{})
	ObufType = reflect.TypeOf(Obuf{})
	LenType  = reflect.TypeOf(Len(0))
	OffType  = reflect.TypeOf(Off(0))
	FdType   = reflect.TypeOf(Fd(0))
	PtrType  = reflect.TypeOf(Ptr(0))
)
