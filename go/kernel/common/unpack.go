package common

import (
	"github.com/lunixbochs/argjoy"
	"reflect"
)

type Unpacker func(Buf, []uint64, interface{}) error

func (k *KernelBase) unpack(arg interface{}, vals []interface{}) error {
	// guard against null pointers
	if v, ok := vals[0].(uint64); ok && v == 0 {
		return nil
	}
	e := reflect.ValueOf(k.UsercornKernel()).Elem()
	unpackField := e.FieldByName("Unpack")
	if unpackField.IsValid() {
		unpack := unpackField.Interface().(Unpacker)
		regs := make([]uint64, len(vals))
		for i, v := range vals {
			regs[i] = v.(uint64)
		}
		buf := NewBuf(k.U, regs[0])
		if err := unpack(buf, regs, arg); err != nil {
			return err
		}
		return nil
	}
	return argjoy.NoMatch
}
