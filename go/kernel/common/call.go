package common

import (
	"fmt"
	"reflect"
)

// Call a syscall from the dispatch table. Will panic() if anything goes terribly wrong.
func (sys Syscall) Call(args []uint64) uint64 {
	kernel := sys.Instance.Interface().(Kernel)
	kernelBase := kernel.UsercornKernel()
	in := make([]reflect.Value, len(sys.In)+1)
	in[0] = sys.Instance
	// collect and cast syscall arguments
	for i, typ := range sys.In {
		var val reflect.Value
		if i >= len(args) {
			panic(fmt.Errorf("Not enough arguments to syscall '%s'. Wanted %d, got %d.", sys.Name, len(sys.In), len(args)))
		}
		arg := args[i]
		argVal := reflect.ValueOf(arg)
		switch typ {
		case BufType, ObufType:
			val = reflect.ValueOf(NewBuf(kernelBase.U, arg)).Convert(typ)
		case LenType, OffType, FdType, PtrType:
			val = argVal.Convert(typ)
		default:
			switch typ.Kind() {
			case reflect.String:
				s, _ := kernelBase.U.Mem().ReadStrAt(arg)
				val = reflect.ValueOf(s)
			default:
				if argVal.Type().ConvertibleTo(typ) {
					val = argVal.Convert(typ)
				} else {
					if v, err := sys.Unpack(args[i:], typ); err == nil {
						val = v
					} else {
						panic(fmt.Errorf("error while unpacking %s(..%s..): '%s'", sys.Name, typ, err))
					}
				}
			}
		}
		in[i+1] = val
	}
	// call handler function
	out := sys.Method.Func.Call(in)
	// return output if first return of function is representable as an int type
	Uint64Type := reflect.TypeOf(uint64(0))
	if len(out) > 0 && out[0].Type().ConvertibleTo(Uint64Type) {
		return out[0].Convert(Uint64Type).Uint()
	}
	return 0
}
