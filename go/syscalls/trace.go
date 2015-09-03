package syscalls

import (
	"fmt"
	"os"
	"strings"

	"../models"
)

const (
	INT = iota
	FD
	STR
	BUF
	OBUF
	LEN
	OFF
	PTR
)

func traceArgs(u models.Usercorn, name string, args []uint64) string {
	types := syscalls[name].Args
	ret := make([]string, 0, len(types))
	for i, t := range types {
		var s string
		switch t {
		case INT, FD:
			s = fmt.Sprintf("%d", int32(args[i]))
		case STR:
			s, _ = u.MemReadStr(args[i])
			s = fmt.Sprintf("%#v", s)
		case BUF:
			mem, _ := u.MemRead(args[i], args[i+1])
			s = fmt.Sprintf("%#v", string(mem))
		default:
			s = fmt.Sprintf("0x%x", args[i])
		}
		ret = append(ret, s)
	}
	return strings.Join(ret, ", ")
}

func Trace(u models.Usercorn, name string, args []uint64) {
	fmt.Fprintf(os.Stderr, "%s(%s)", name, traceArgs(u, name, args))
}

func TraceRet(u models.Usercorn, name string, args []uint64, ret uint64) {
	types := syscalls[name].Args
	var out []string
	for i, t := range types {
		if t == OBUF {
			r := int(ret)
			if uint64(r) <= args[i+1] && r >= 0 {
				mem, _ := u.MemRead(args[i], uint64(r))
				out = append(out, fmt.Sprintf("%#v", string(mem)))
			}
		}
	}
	out = append(out, fmt.Sprintf("0x%x", ret))
	fmt.Fprintf(os.Stderr, " = %s\n", strings.Join(out, ", "))
}
