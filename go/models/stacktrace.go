package models

import (
	"fmt"
	"os"
)

type stackFrame struct {
	PC, SP uint64
	Sym    string
}

type Stacktrace struct {
	Stack []stackFrame
}

func (s *Stacktrace) Len() int {
	return len(s.Stack)
}

func (s *Stacktrace) Print(u Usercorn) {
	pc, _ := u.RegRead(u.Arch().PC)
	sp, _ := u.RegRead(u.Arch().SP)
	sym, _ := u.Symbolicate(pc)
	stack := append(s.Stack, stackFrame{pc, sp, sym})
	for i := len(stack) - 1; i >= 0; i-- {
		frame := stack[i]
		fmt.Fprintf(os.Stderr, "  0x%x %s\n", frame.PC, frame.Sym)
	}
}

func (s *Stacktrace) Push(pc, sp uint64, sym string) {
	s.Stack = append(s.Stack, stackFrame{pc, sp, sym})
}

func (s *Stacktrace) Empty() bool {
	return s.Len() == 0
}

func (s *Stacktrace) Peek() stackFrame {
	if s.Empty() {
		return stackFrame{}
	}
	return s.Stack[s.Len()-1]
}

func (s *Stacktrace) Pop() stackFrame {
	if s.Empty() {
		return stackFrame{}
	}
	ret := s.Peek()
	s.Stack = s.Stack[:s.Len()-1]
	return ret
}

func (s *Stacktrace) Update(pc, sp uint64, sym string) {
	if s.Empty() || sp < s.Peek().SP {
		s.Push(pc, sp, sym)
	} else {
		for !s.Empty() && sp > s.Peek().SP {
			s.Pop()
		}
	}
}
