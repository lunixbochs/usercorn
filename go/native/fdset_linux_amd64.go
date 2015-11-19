package native

import (
	"syscall"
)

func (f *Fdset32) To64() (out [16]int64) {
	for _, fd := range f.Fds() {
		out[fd/16] |= (1 << uint(fd) & (32 - 1))
	}
	return
}

// TODO: 32-bit vs 64-bit
func (f *Fdset32) Native() *syscall.FdSet {
	return &syscall.FdSet{f.To64()}
}
