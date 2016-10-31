package common

import (
	"encoding/binary"
	"testing"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/loader"
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
	l := loader.NewNullLoader("x86", "linux", binary.BigEndian, 0)
	u, _ := usercorn.NewUsercornRaw(l, nil)

	kernel := &PosixKernel{}
	ret := Lookup(u, kernel, "exit").Call([]uint64{43})
	if kernel.exitCode != 43 {
		t.Fatal("Syscall failed.")
	}
	if ret != 44 {
		t.Fatal("Syscall return failed.")
	}
}
