package common

import (
	"reflect"
)

type Unpacker func(Buf, []uint64, interface{}) error

func (sys Syscall) Unpack(args []uint64, typ reflect.Type) (reflect.Value, error) {
	e := sys.Instance.Elem()
	u := sys.Instance.Interface().(Kernel).Usercorn()
	buf := NewBuf(u, args[0])
	unpack := e.FieldByName("Unpack").Interface().(Unpacker)
	if unpack != nil {
		var tmp reflect.Value
		if typ.Kind() == reflect.Ptr {
			tmp = reflect.New(typ.Elem())
		} else {
			tmp = reflect.New(typ)
		}
		if err := unpack(buf, args, tmp.Interface()); err != nil {
			return reflect.Value{}, err
		} else {
			if typ.Kind() == reflect.Ptr {
				return tmp, nil
			}
			return tmp.Elem(), nil
		}
	}
	return reflect.Value{}, NoUnpackHandler
}
