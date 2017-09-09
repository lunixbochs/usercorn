package models

type Stackframe struct {
	PC, SP uint64
}

type Callstack struct {
	Stack []Stackframe
}

func (s *Callstack) Len() int {
	return len(s.Stack)
}

func (s *Callstack) Freeze(pc, sp uint64) []Stackframe {
	if s.Empty() || s.Peek().PC != pc {
		return append(s.Stack, Stackframe{pc, sp})
	}
	return s.Stack
}

func (s *Callstack) Push(pc, sp uint64) {
	s.Stack = append(s.Stack, Stackframe{pc, sp})
}

func (s *Callstack) Empty() bool {
	return s.Len() == 0
}

func (s *Callstack) Peek() Stackframe {
	if s.Empty() {
		return Stackframe{}
	}
	return s.Stack[s.Len()-1]
}

func (s *Callstack) Pop() Stackframe {
	if s.Empty() {
		return Stackframe{}
	}
	ret := s.Peek()
	s.Stack = s.Stack[:s.Len()-1]
	return ret
}

func (s *Callstack) Update(pc, sp uint64) {
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
