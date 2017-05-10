package native

import (
	"syscall"
)

func (f *Fdset32) Native() *syscall.FdSet {
	return &syscall.FdSet{Bits: f.Bits}
}
