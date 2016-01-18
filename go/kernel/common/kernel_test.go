package common

import (
	"testing"

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

func TestKernel(t *testing.T) {
	u := &mock.Usercorn{}
	kernel := &PosixKernel{}
	ret := Lookup(u, kernel, "exit").Call([]uint64{43})
	if kernel.exitCode != 43 {
		t.Fatal("Syscall failed.")
	}
	if ret != 44 {
		t.Fatal("Syscall return failed.")
	}
}
