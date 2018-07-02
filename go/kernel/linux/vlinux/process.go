package vlinux

import "github.com/lunixbochs/usercorn/go/models"

// Exit sycall
func (k *VirtualLinuxKernel) Exit(code int) {
	k.U.Exit(models.ExitStatus(code))
}

// ExitGroup syscall
func (k *VirtualLinuxKernel) ExitGroup(code int) {
	k.Exit(code)
}
