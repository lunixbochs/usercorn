package common

import (
	"reflect"
	"strings"
	"unicode"

	"github.com/lunixbochs/usercorn/go/models"
)

type Syscall struct {
	Name     string
	Instance reflect.Value
	Method   reflect.Method
	In       []reflect.Type
	Out      []reflect.Type
}

func (s Syscall) U() models.Usercorn {
	return s.Instance.Interface().(Kernel).Usercorn()
}

type Kernel interface {
	Usercorn() models.Usercorn
	UsercornKernel() *KernelBase
	UsercornInit(Kernel)
	UsercornSyscall(name string) *Syscall
}

type KernelBase struct {
	Syscalls map[string]Syscall
	U        models.Usercorn
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
		name := method.Name
		if !strings.HasPrefix(name, "Usercorn") {
			if strings.HasPrefix(name, "Literal") {
				name = strings.Replace(name, "Literal", "", 1)
			}
			name = camelToSnakeCase(name)
			in := make([]reflect.Type, method.Type.NumIn()-1)
			for j := 1; j < method.Type.NumIn(); j++ {
				in[j-1] = method.Type.In(j)
			}
			out := make([]reflect.Type, method.Type.NumOut())
			for j := 0; j < method.Type.NumOut(); j++ {
				out[j] = method.Type.Out(j)
			}
			syscalls[name] = Syscall{
				Name:     name,
				Instance: instance, Method: method,
				In: in, Out: out,
			}
		}
	}
}

func (k *KernelBase) UsercornSyscall(name string) *Syscall {
	if sys, ok := k.Syscalls[name]; ok {
		return &sys
	}
	return nil
}
