package common

import (
	"reflect"

	"github.com/lunixbochs/usercorn/go/models"
)

type (
	Buf struct {
		Addr uint64
		*models.StrucStream
	}
	Obuf struct {
		Addr uint64
		*models.StrucStream
	}
	Len uint64
	Off int64
	Fd  int
	Ptr uint64
)

var (
	BufType  = reflect.TypeOf(Buf{})
	ObufType = reflect.TypeOf(Obuf{})
	LenType  = reflect.TypeOf(Len(0))
	OffType  = reflect.TypeOf(Off(0))
	FdType   = reflect.TypeOf(Fd(0))
	PtrType  = reflect.TypeOf(Ptr(0))
)
