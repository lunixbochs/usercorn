package common

import (
	"testing"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/models"
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
	u, err := usercorn.NewUsercorn("../../../bins/x86.linux.elf", "")
	if err != nil {
		t.Fatal(err)
	}
	kernel := NewPosixKernel(u)
	ret := kernel.UsercornCall("exit", []uint64{43})
	if kernel.exitCode != 43 {
		t.Fatal("Syscall failed.")
	}
	if ret != 44 {
		t.Fatal("Syscall return failed.")
	}
}
