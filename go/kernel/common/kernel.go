package common

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/lunixbochs/usercorn/go/models"
)

type Syscall struct {
	Instance reflect.Value
	Method   reflect.Method
	In       []reflect.Type
	Out      []reflect.Type
}

type Kernel interface {
	UsercornKernel() *KernelBase
	UsercornInit(Kernel)
	UsercornCall(name string, args []uint64) uint64
}

type KernelBase struct {
	Syscalls map[string]Syscall
	U        models.Usercorn
}

func (k *KernelBase) UsercornKernel() *KernelBase {
	return k
}

func camelToSnakeCase(name string) string {
	var words []string
	last := 0
	for i, c := range name {
		if unicode.IsUpper(c) {
			if i > 0 {
				words = append(words, name[last:i])
			}
			last = i
		}
	}
	words = append(words, name[last:])
	return strings.ToLower(strings.Join(words, "_"))
}

/*
   k.UsercornInit() fills out the Syscall table and is only a method of Kernel for convenience.
   It requires an interface reference to the final structure, so
   structures embedding the Kernel type should manually call Kernel.UsercornInit(self), like so:

   type PosixKernel struct {
		Kernel
   }

   func NewPosixKernel(u models.Usercorn) *PosixKernel {
	   kernel := &PosixKernel{U: u}
	   kernel.UsercornInit(kernel)
	   return kernel
   }
*/
func (k *KernelBase) UsercornInit(i Kernel) {
	syscalls := make(map[string]Syscall)
	k.Syscalls = syscalls
	typ := reflect.TypeOf(i)
	instance := reflect.ValueOf(i)
	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		if !strings.HasPrefix(method.Name, "Usercorn") {
			name := camelToSnakeCase(method.Name)
			in := make([]reflect.Type, method.Type.NumIn()-1)
			for j := 1; j < method.Type.NumIn(); j++ {
				in[j-1] = method.Type.In(j)
			}
			out := make([]reflect.Type, method.Type.NumOut())
			for j := 0; j < method.Type.NumOut(); j++ {
				out[j] = method.Type.Out(j)
			}
			syscalls[name] = Syscall{Instance: instance, Method: method, In: in, Out: out}
		}
	}
}

// Call a syscall from the dispatch table. Will panic() if anything goes terribly wrong.
func (k *KernelBase) UsercornCall(name string, args []uint64) uint64 {
	sys, ok := k.Syscalls[name]
	if !ok {
		panic(fmt.Errorf("Unknown syscall: %s", name))
	}
	in := make([]reflect.Value, len(sys.In)+1)
	in[0] = sys.Instance
	for i, typ := range sys.In {
		var val reflect.Value
		if i >= len(args) {
			panic(fmt.Errorf("Not enough arguments to syscall '%s'. Wanted %d, got %d.", name, len(sys.In), len(args)))
		}
		arg := args[i]
		argVal := reflect.ValueOf(arg)
		switch typ {
		case BufType, ObufType:
			val = reflect.ValueOf(Obuf{Addr: arg, StrucStream: k.U.StrucAt(arg)}).Convert(typ)
		case LenType, OffType, FdType, PtrType:
			val = argVal.Convert(typ)
		default:
			switch val.Kind() {
			case reflect.String:
				s, _ := k.U.Mem().ReadStrAt(arg)
				val = reflect.ValueOf(s)
			default:
				if argVal.Type().ConvertibleTo(typ) {
					val = argVal.Convert(typ)
				} else {
					panic(fmt.Errorf("Unsupported syscall argument type %s(..%s..)", name, typ))
				}
			}
		}
		in[i+1] = val
	}
	out := sys.Method.Func.Call(in)
	if len(out) > 0 && out[0].Type().ConvertibleTo(reflect.TypeOf(0)) {
		return out[0].Uint()
	}
	return 0
}
