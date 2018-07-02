// Package vlinux provides a kernel that wants to separate the
// running process from the host system.
package vlinux

import (
	"fmt"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
)

// MinusOne represents -1 when interpreted as signed integer.
// This is often used to indicate an error.
const MinusOne = 0xFFFFFFFFFFFFFFFF

// VirtualLinuxKernel is a kernel that isolates processes from the host.
type VirtualLinuxKernel struct {
	*co.KernelBase
	Unpack func(co.Buf, interface{})
	Files  map[string]File
	// Fds holds the open filedescriptors
	Fds map[co.Fd]*Fd
}

// NewVirtualKernel creates a Linux Kernel that is isolated from the operating system.
func NewVirtualKernel() *VirtualLinuxKernel {
	kernel := &VirtualLinuxKernel{
		KernelBase: &co.KernelBase{},
		Files:      map[string]File{},
		Fds:        map[co.Fd]*Fd{},
	}
	kernel.Argjoy.Register(func(arg interface{}, vals []interface{}) error {
		return linux.Unpack(kernel, arg, vals)
	})
	kernel.initFs()
	return kernel
}

func (k *VirtualLinuxKernel) initFs() {
	// Stdout
	k.Fds[1] = &Fd{
		File: &File{
			Stat: syscall.Stat_t{
				Mode: 0x2,
				Size: 0,
			},
		},
		write: func(p []byte) (int, error) {
			fmt.Print(string(p))
			return len(p), nil
		},
	}
}
