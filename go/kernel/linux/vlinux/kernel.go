// Package vlinux provides a kernel that wants to separate the
// running process from the host system.
package vlinux

import (
	"os"

	"github.com/felberj/ramfs"
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
	Fs     *ramfs.Filesystem
	Fds    map[co.Fd]File // Open file descriptors
	nextfd co.Fd
}

// NewVirtualKernel creates a Linux Kernel that is isolated from the operating system.
func NewVirtualKernel() *VirtualLinuxKernel {
	kernel := &VirtualLinuxKernel{
		KernelBase: &co.KernelBase{},
		Fs:         ramfs.New(),
		Fds:        map[co.Fd]File{},
	}
	kernel.Argjoy.Register(func(arg interface{}, vals []interface{}) error {
		return linux.Unpack(kernel, arg, vals)
	})
	kernel.initFs()
	return kernel
}

func (k *VirtualLinuxKernel) initFs() {
	// Stdout
	k.Fds[1] = os.Stdin
	k.nextfd = 3
}
