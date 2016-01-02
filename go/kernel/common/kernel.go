package common

import (
	"github.com/lunixbochs/argjoy"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lunixbochs/usercorn/go/models"
)

type Syscall struct {
	Name     string
	Instance reflect.Value
	Method   reflect.Method
	In       []reflect.Type
	Out      []reflect.Type
	ObufArr  bool
}

func (s Syscall) U() models.Usercorn {
	return s.Instance.Interface().(Kernel).Usercorn()
}

type Kernel interface {
	Usercorn() models.Usercorn
	UsercornKernel() *KernelBase
	UsercornInit(Kernel, models.Usercorn)
	UsercornSyscall(name string) *Syscall
}

type KernelBase struct {
	Syscalls map[string]Syscall
	U        models.Usercorn
	Argjoy   argjoy.Argjoy
}

func (k *KernelBase) Usercorn() models.Usercorn {
	return k.U
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
   It requires an interface reference to the final structure, so structures embedding the
   Kernel type should manually call Kernel.UsercornInit(self), like so:

   type PosixKernel struct {
		KernelBase
   }

   func NewPosixKernel(u models.Usercorn) *PosixKernel {
	   kernel := &PosixKernel{}
	   kernel.UsercornInit(kernel, u)
	   return kernel
   }
*/
func (k *KernelBase) UsercornInit(i Kernel, u models.Usercorn) {
	syscalls := make(map[string]Syscall)
	k.Syscalls = syscalls
	k.U = u
	typ := reflect.TypeOf(i)
	instance := reflect.ValueOf(i)
	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		name := method.Name
		if !strings.HasPrefix(name, "Usercorn") {
			if strings.HasPrefix(name, "Literal") {
				name = strings.Replace(name, "Literal", "", 1)
			} else if r, size := utf8.DecodeRuneInString(name); size <= 0 || !unicode.IsUpper(r) {
				// skip private or broken unicode methods
				continue
			}
			name = camelToSnakeCase(name)
			in := make([]reflect.Type, method.Type.NumIn()-1)
			for j := 1; j < method.Type.NumIn(); j++ {
				in[j-1] = method.Type.In(j)
			}
			obufArr := false
			if len(in) > 0 && in[0] == reflect.SliceOf(reflect.TypeOf(Obuf{})) {
				obufArr = true
				in = in[1:]
			}
			out := make([]reflect.Type, method.Type.NumOut())
			for j := 0; j < method.Type.NumOut(); j++ {
				out[j] = method.Type.Out(j)
			}
			syscalls[name] = Syscall{
				Name:     name,
				Instance: instance, Method: method,
				In: in, Out: out,
				ObufArr: obufArr,
			}
		}
	}
	k.Argjoy.Register(k.commonArgCodec)
	k.Argjoy.Register(argjoy.IntToInt)
}

func (k *KernelBase) UsercornSyscall(name string) *Syscall {
	if sys, ok := k.Syscalls[name]; ok {
		return &sys
	}
	return nil
}
