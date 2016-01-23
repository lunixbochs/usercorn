package common

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

func (s Syscall) traceArg(args ...interface{}) string {
	hex := func(a interface{}) string { return fmt.Sprintf("0x%x", a) }

	switch arg := args[0].(type) {
	case Obuf:
		return hex(arg.Addr)
	case Buf:
		if len(args) > 1 {
			strsize := s.Kernel.U.Config().Strsize
			if length, ok := args[1].(Len); ok {
				if int(length) > strsize && strsize > 0 {
					length = Len(strsize)
				}
				mem, _ := s.Kernel.U.MemRead(arg.Addr, uint64(length))
				return models.Repr(mem)
			}
		}
		return hex(arg.Addr)
	case Off:
		return hex(arg)
	case Ptr:
		return hex(arg)
	case Fd:
		return fmt.Sprintf("%d", int32(arg))
	case string:
		strsize := s.Kernel.U.Config().Strsize
		if len(arg) > strsize && strsize > 0 {
			arg = arg[:strsize]
		}
		return models.Repr([]byte(arg))
	case uint64:
		return hex(arg)
	default:
		return fmt.Sprintf("%v", arg)
	}
}

func (s Syscall) traceArgs(regs []uint64) string {
	inRef, err := s.Kernel.Argjoy.Convert(s.In, false, regs)
	if err != nil {
		return err.Error()
	}
	in := make([]interface{}, len(inRef))
	for i, val := range inRef {
		in[i] = val.Interface()
	}
	ret := make([]string, len(in))
	for i := range in {
		ret[i] = s.traceArg(in[i:]...)
	}
	return strings.Join(ret, ", ")
}

func (s Syscall) Trace(regs []uint64) {
	fmt.Fprintf(os.Stderr, "%s(%s)", s.Name, s.traceArgs(regs))
}

func (s Syscall) TraceRet(args []uint64, ret uint64) {
	var out []string
	for i, typ := range s.In {
		if typ == reflect.TypeOf(Obuf{}) && len(args) > i+1 {
			length := int(ret)
			if uint64(length) <= args[i+1] && length >= 0 {
				strsize := s.Kernel.U.Config().Strsize
				if length > strsize && strsize > 0 {
					length = strsize
				}
				mem, _ := s.Kernel.U.MemRead(args[i], uint64(length))
				out = append(out, models.Repr(mem))
			}
		}
	}
	if len(s.Out) > 0 {
		// TODO: need a standard for converting return values
		out = append(out, s.traceArg(ret))
	}
	if len(out) > 0 {
		fmt.Fprintf(os.Stderr, " = %s\n", strings.Join(out, ", "))
	} else {
		fmt.Fprintf(os.Stderr, "\n")
	}
}
