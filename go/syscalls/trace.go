package syscalls

import (
	"fmt"
	"os"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

const (
	INT = iota
	ENUM
	FD
	STR
	BUF
	OBUF
	LEN
	OFF
	PTR
	PID
	SIGNAL
)

func traceBasicArg(u models.Usercorn, arg uint64, t int) string {
	switch t {
	case INT, FD:
		return fmt.Sprintf("%d", int32(arg))
	case STR:
		s, _ := u.Mem().ReadStrAt(arg)
		return fmt.Sprintf("%+q", s)
	default:
		return fmt.Sprintf("0x%x", arg)
	}
}

func traceArg(u models.Usercorn, args []uint64, t int) string {
	switch t {
	case BUF:
		mem, _ := u.MemRead(args[0], args[1])
		return fmt.Sprintf("%+q", string(mem))
	default:
		return traceBasicArg(u, args[0], t)
	}
}

func (s Syscall) traceArgs(u models.Usercorn, args []uint64) string {
	types := s.Args
	ret := make([]string, 0, len(types))
	for i, t := range types {
		ret = append(ret, traceArg(u, args[i:], t))
	}
	return strings.Join(ret, ", ")
}

func (s Syscall) Trace(u models.Usercorn, name string, args []uint64) {
	fmt.Fprintf(os.Stderr, "%s(%s)", name, s.traceArgs(u, args))
}

func (s Syscall) TraceRet(u models.Usercorn, name string, args []uint64, ret uint64) {
	types := syscalls[name].Args
	var out []string
	for i, t := range types {
		if t == OBUF {
			r := int(ret)
			if uint64(r) <= args[i+1] && r >= 0 {
				mem, _ := u.MemRead(args[i], uint64(r))
				out = append(out, fmt.Sprintf("%+q", string(mem)))
			}
		}
	}
	out = append(out, traceBasicArg(u, ret, s.Ret))
	fmt.Fprintf(os.Stderr, " = %s\n", strings.Join(out, ", "))
}
