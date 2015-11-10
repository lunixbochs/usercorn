package native

import (
	"syscall"
)

func (f *Fdset32) Native() *syscall.FdSet {
	return &syscall.FdSet{f.Bits}
}
