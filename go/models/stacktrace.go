package models

import (
	"fmt"
	"os"
)

type Stacktrace struct {
	Stack []uint64
	oldSP uint64
}

func (s *Stacktrace) Print(u Usercorn) {
	for i := len(s.Stack) - 1; i >= 0; i-- {
		addr := s.Stack[i]
		sym, _ := u.Symbolicate(addr)
		fmt.Fprintf(os.Stderr, "  0x%x %s\n", addr, sym)
	}
}

func (s *Stacktrace) Push(addr uint64) {
	s.Stack = append(s.Stack, addr)
}

func (s *Stacktrace) Pop() uint64 {
	if len(s.Stack) == 0 {
		return 0
	}
	ret := s.Stack[len(s.Stack)-1]
	s.Stack = s.Stack[len(s.Stack)-1:]
	return ret
}

func (s *Stacktrace) Update(addr, sp uint64) {
	if sp < s.oldSP {
		s.Push(addr)
	} else if s.oldSP < sp {
		s.Pop()
	}
	s.oldSP = sp
}
