package common

import (
	"testing"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/mock"
)

type PosixKernel struct {
	KernelBase
	exitCode int
}

func (k *PosixKernel) Exit(code int) uint64 {
	k.exitCode = code
	return 44
}

func NewPosixKernel(u models.Usercorn) *PosixKernel {
	kernel := &PosixKernel{KernelBase{U: u}, 0}
	kernel.UsercornInit(kernel)
	return kernel
}

func TestKernel(t *testing.T) {
	u := &mock.Usercorn{}
	kernel := NewPosixKernel(u)
	ret := kernel.UsercornSyscall("exit").Call([]uint64{43})
	if kernel.exitCode != 43 {
		t.Fatal("Syscall failed.")
	}
	if ret != 44 {
		t.Fatal("Syscall return failed.")
	}
}
