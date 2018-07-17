package common

import (
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/lunixbochs/argjoy"
	"github.com/lunixbochs/usercorn/go/models"
)

type KernelBase struct {
	Syscalls map[string]Syscall
	U        models.Usercorn
	Argjoy   argjoy.Argjoy
	Pack     func(b Buf, i interface{}) error
}

func (k *KernelBase) UsercornKernel() *KernelBase {
	return k
}

type Kernel interface {
	UsercornKernel() *KernelBase
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

func initKernel(kf Kernel) {
	k := kf.UsercornKernel()
	k.Syscalls = make(map[string]Syscall)
	instance := reflect.ValueOf(kf)
	typ := instance.Type()
	for i := 0; i < typ.NumMethod(); i++ {
		method := typ.Method(i)
		name := method.Name
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
		uintArr := false
		if len(in) > 0 {
			if in[0] == reflect.SliceOf(reflect.TypeOf(Obuf{})) {
				obufArr = true
			} else if in[0] == reflect.SliceOf(reflect.TypeOf(uint64(0))) {
				uintArr = true
			}
		}
		if obufArr || uintArr {
			in = in[1:]
		}
		out := make([]reflect.Type, method.Type.NumOut())
		for j := 0; j < method.Type.NumOut(); j++ {
			out[j] = method.Type.Out(j)
		}
		k.Syscalls[name] = Syscall{
			Name:     name,
			Kernel:   k,
			Instance: instance,
			Method:   method,
			In:       in,
			Out:      out,
			ObufArr:  obufArr,
		}
	}
	k.Argjoy.Register(k.commonArgCodec)
	k.Argjoy.Register(argjoy.IntToInt)
}

func Lookup(u models.Usercorn, kf Kernel, name string) *Syscall {
	k := kf.UsercornKernel()
	k.U = u
	if k.Syscalls == nil {
		initKernel(kf)
	}
	if sys, ok := k.Syscalls[name]; ok {
		return &sys
	}
	return nil
}
