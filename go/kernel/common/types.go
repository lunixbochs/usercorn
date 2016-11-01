package common

import (
	"github.com/lunixbochs/argjoy"
	"os"

	"github.com/lunixbochs/usercorn/go/models"
)

type (
	Buf struct {
		Addr uint64
		K    *KernelBase
	}
	Obuf struct{ Buf }
	Len  uint64
	Off  int64
	Fd   int32
	Ptr  uint64
)

func NewBuf(k Kernel, addr uint64) Buf {
	return Buf{K: k.UsercornKernel(), Addr: addr}
}

func (b Buf) Struc() *models.StrucStream {
	return b.K.U.StrucAt(b.Addr)
}

func (b Buf) Pack(i interface{}) error {
	if b.K.Pack != nil {
		if err := b.K.Pack(b, i); err == nil {
			return nil
		} else if err != argjoy.NoMatch {
			return err
		}
	}
	return b.Struc().Pack(i)
}

func (b Buf) Unpack(i interface{}) error {
	return b.Struc().Unpack(i)
}

func (b Buf) Sizeof(i interface{}) (int, error) {
	return b.Struc().Sizeof(i)
}

func (f Fd) File() *os.File {
	return os.NewFile(uintptr(f), "")
}
