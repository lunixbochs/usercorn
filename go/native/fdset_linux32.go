// +build 386 arm
// +build linux

package native

import (
	"syscall"
)

// TODO: 32-bit vs 64-bit
func (f *Fdset32) Native() *syscall.FdSet {
	return &syscall.FdSet{f.Bits}
}
