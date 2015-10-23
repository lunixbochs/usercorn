package models

type Loop struct {
	Loop          []uint64
	Index, Filled int
}

func NewLoop(length int) *Loop {
	return &Loop{make([]uint64, length), 0, 0}
}

func (l *Loop) Inc() {
	if l.Index > l.Filled {
		l.Filled = l.Index
	}
	l.Index = (l.Index + 1) % len(l.Loop)
}

func (l *Loop) Push(n uint64) {
	l.Loop[l.Index] = n
	l.Inc()
}

func (l *Loop) Next() uint64 {
	n := l.Loop[l.Index]
	l.Inc()
	return n
}

func (l *Loop) Ring(start int, dst []uint64) []uint64 {
	i := 0
	for i < len(dst) {
		idx := (l.Index - 1 + start + i) % len(l.Loop)
		for idx < 0 {
			idx += len(l.Loop)
		}
		if idx > l.Filled {
			dst = dst[:len(dst)-1]
		} else {
			dst[i] = l.Loop[idx]
			i++
		}
	}
	return dst
}

type LoopDetect struct {
	History, Loop *Loop
	Loops, Len    int
}

func NewLoopDetect(length int) *LoopDetect {
	return &LoopDetect{
		History: NewLoop(length * 2),
		Len:     length,
	}
}

func (l *LoopDetect) Update(addr uint64) (bool, []uint64, int) {
	if l.Loop != nil {
		loop := l.Loop
		idx := loop.Index
		next := loop.Next()
		if next == addr {
			if idx == 0 {
				l.Loops++
			}
			return true, loop.Loop, l.Loops
		} else {
			loops := l.Loops
			l.Loop = nil
			l.Loops = 0
			return false, loop.Loop, loops
		}
	}
	l.History.Push(addr)
	loop := l.Detect()
	if loop != nil {
		l.Loop = loop
		l.Loops = 1
		return true, loop.Loop, l.Loops
	}
	return false, nil, 0
}

func (l *LoopDetect) Detect() *Loop {
	equals := func(a, b []uint64, length int) bool {
		if len(a) != len(b) || len(a) == 0 || len(a) != length {
			return false
		}
		for i, v := range a {
			if b[i] != v {
				return false
			}
		}
		return true
	}
	// TODO: stack allocate if len is short?
	// we need to return test[:n] so it only works for cmp
	test := make([]uint64, l.Len)
	cmp := make([]uint64, l.Len)
	min := l.Len
	alt := (l.History.Filled + 1) / 2
	if alt < min {
		min = alt
	}
	for n := 1; n <= min; n++ {
		loop := l.History.Ring(-n+1, test[:n])
		cmp := l.History.Ring(-n*2+1, cmp[:n])
		if equals(loop, cmp, n) {
			return &Loop{loop, 0, 0}
		}
	}
	return nil
}
