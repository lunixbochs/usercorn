package common

import (
	"reflect"
)

type Unpacker func(Buf, []uint64, interface{}) bool

func (sys Syscall) Unpack(args []uint64, typ reflect.Type) (reflect.Value, bool) {
	e := sys.Instance.Elem()
	u := sys.Instance.Interface().(Kernel).Usercorn()
	buf := NewBuf(u, args[0])
	unpack := e.FieldByName("Unpack").Interface().(Unpacker)
	if unpack != nil {
		tmp := reflect.New(typ)
		if unpack(buf, args, tmp.Interface()) {
			return tmp.Elem(), true
		}
	}
	return reflect.Value{}, false
}
