package common

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

func (s Syscall) traceArg(args []uint64, typ reflect.Type) string {
	if typ == BufType && len(args) > 1 {
		mem, _ := s.U().MemRead(args[0], args[1])
		return models.Repr(mem)
	}
	switch typ {
	case BufType, ObufType, OffType, PtrType:
		return fmt.Sprintf("0x%x", args[0])
	case LenType, FdType:
		return fmt.Sprintf("%d", args[0])
	default:
		switch typ.Kind() {
		case reflect.String:
			s, _ := s.U().Mem().ReadStrAt(args[0])
			return models.Repr([]byte(s))
		case reflect.Uint64:
			return fmt.Sprintf("0x%x", args[0])
		default:
			// TODO: facilitate pretty printing?
			if v, err := s.Unpack(args, typ); err == nil {
				return fmt.Sprintf("%v", v.Interface())
			}
			return fmt.Sprintf("%d", int32(args[0]))
		}
	}
}

func (s Syscall) traceArgs(args []uint64) string {
	ret := make([]string, 0, len(s.In))
	for i, typ := range s.In {
		ret = append(ret, s.traceArg(args[i:], typ))
	}
	return strings.Join(ret, ", ")
}

func (s Syscall) Trace(args []uint64) {
	fmt.Fprintf(os.Stderr, "%s(%s)", s.Name, s.traceArgs(args))
}

func (s Syscall) TraceRet(args []uint64, ret uint64) {
	var out []string
	for i, typ := range s.In {
		if typ == ObufType && len(args) > i+1 {
			r := int(ret)
			if uint64(r) <= args[i+1] && r >= 0 {
				mem, _ := s.U().MemRead(args[i], uint64(r))
				out = append(out, models.Repr(mem))
			}
		}
	}
	if len(s.Out) > 0 {
		out = append(out, s.traceArg([]uint64{ret}, s.Out[0]))
	}
	if len(out) > 0 {
		fmt.Fprintf(os.Stderr, " = %s\n", strings.Join(out, ", "))
	} else {
		fmt.Fprintf(os.Stderr, "\n")
	}
}
