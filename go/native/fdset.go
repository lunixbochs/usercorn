package native

import (
	"fmt"
)

type Fdset32 struct {
	Bits [32]int32
}

func (f *Fdset32) Set(fd int) {
	f.Bits[fd/32] |= (1 << (uint(fd) & (32 - 1)))
}

func (f *Fdset32) Clear(fd int) {
	f.Bits[fd/32] &= ^(1 << (uint(fd) & (32 - 1)))
}

func (f *Fdset32) IsSet(fd int) bool {
	return f.Bits[fd/32]&(1<<(uint(fd)&(32-1))) != 0
}

func (f *Fdset32) Fds() []int {
	var out []int
	for fd := 0; fd < 1024; fd++ {
		if f.IsSet(fd) {
			out = append(out, fd)
		}
	}
	return out
}

func (f *Fdset32) String() string {
	return fmt.Sprintf("%v", f.Fds())
}
