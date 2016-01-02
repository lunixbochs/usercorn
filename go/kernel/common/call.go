package common

import (
	"github.com/lunixbochs/argjoy"
	"reflect"
)

func (k *KernelBase) commonArgCodec(arg interface{}, vals []interface{}) error {
	if reg, ok := vals[0].(uint64); ok {
		switch v := arg.(type) {
		case *Buf:
			*v = NewBuf(k.U, reg)
		case *Obuf:
			*v = Obuf(NewBuf(k.U, reg))
		case *Len:
			*v = Len(reg)
		case *Off:
			*v = Off(reg)
		case *Fd:
			*v = Fd(reg)
		case *Ptr:
			*v = Ptr(reg)
		case *string:
			s, err := k.U.Mem().ReadStrAt(reg)
			if err != nil {
				return err
			}
			*v = s
		default:
			return argjoy.NoMatch
		}
		return nil
	}
	return argjoy.NoMatch
}

// Call a syscall from the dispatch table. Will panic() if anything goes terribly wrong.
func (sys Syscall) Call(args []uint64) uint64 {
	kernel := sys.Instance.Interface().(Kernel)
	kernelBase := kernel.UsercornKernel()
	extraArgs := 1
	if sys.ObufArr {
		extraArgs += 1
	}
	in := make([]reflect.Value, len(sys.In)+extraArgs)
	in[0] = sys.Instance
	// special case "all args" buf list
	if sys.ObufArr {
		arr := make([]Obuf, len(sys.In)-1)
		for i := range arr {
			arr[i] = Obuf(NewBuf(kernelBase.U, args[i]))
		}
		in[1] = reflect.ValueOf(arr)
	}
	// convert syscall arguments
	converted, err := kernelBase.Argjoy.Convert(sys.In, false, args)
	if err != nil {
		panic(err)
	}
	copy(in[extraArgs:], converted)
	// call handler function
	out := sys.Method.Func.Call(in)
	// return output if first return of function is representable as an int type
	Uint64Type := reflect.TypeOf(uint64(0))
	if len(out) > 0 && out[0].Type().ConvertibleTo(Uint64Type) {
		return out[0].Convert(Uint64Type).Uint()
	}
	return 0
}
