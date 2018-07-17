package vlinux

import "github.com/lunixbochs/usercorn/go/models"

// Exit sycall
func (k *VirtualLinuxKernel) Exit(code uint64) {
	k.U.Exit(models.ExitStatus(code))
}

// ExitGroup syscall
func (k *VirtualLinuxKernel) ExitGroup(code uint64) {
	k.Exit(code)
}

// Ugetrlimit syscall (not implemented)
func (k *VirtualLinuxKernel) Ugetrlimit() {}

// Getrlimit syscall (not implemented)
func (k *VirtualLinuxKernel) Getrlimit() {}
