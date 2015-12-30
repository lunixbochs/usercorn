package models

import (
	"fmt"
)

type Stackframe struct {
	PC, SP uint64
}

func (s *Stackframe) Pretty(u Usercorn) string {
	sym, _ := u.Symbolicate(s.PC, true)
	return fmt.Sprintf("0x%x %s", s.PC, sym)
}

type Stacktrace struct {
	Stack []Stackframe
}

func (s *Stacktrace) Len() int {
	return len(s.Stack)
}

func (s *Stacktrace) Freeze(pc, sp uint64) []Stackframe {
	if s.Empty() || s.Peek().PC != pc {
		return append(s.Stack, Stackframe{pc, sp})
	}
	return s.Stack
}

func (s *Stacktrace) Push(pc, sp uint64) {
	s.Stack = append(s.Stack, Stackframe{pc, sp})
}

func (s *Stacktrace) Empty() bool {
	return s.Len() == 0
}

func (s *Stacktrace) Peek() Stackframe {
	if s.Empty() {
		return Stackframe{}
	}
	return s.Stack[s.Len()-1]
}

func (s *Stacktrace) Pop() Stackframe {
	if s.Empty() {
		return Stackframe{}
	}
	ret := s.Peek()
	s.Stack = s.Stack[:s.Len()-1]
	return ret
}

func (s *Stacktrace) Update(pc, sp uint64) {
	if s.Empty() || sp < s.Peek().SP {
		s.Push(pc, sp)
	} else {
		if sp == s.Peek().SP {
			s.Stack[s.Len()-1].PC = pc
		} else {
			for !s.Empty() && sp > s.Peek().SP {
				s.Pop()
			}
		}
	}
}
