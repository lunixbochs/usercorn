package common

import (
	"github.com/lunixbochs/argjoy"
	"github.com/pkg/errors"
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
	return errors.Wrap(b.Struc().Pack(i), "struc.Pack() failed")
}

func (b Buf) Unpack(i interface{}) error {
	return errors.Wrap(b.Struc().Unpack(i), "struc.Unpack() failed")
}

func (b Buf) Sizeof(i interface{}) (int, error) {
	n, err := b.Struc().Sizeof(i)
	return n, errors.Wrap(err, "struc.Sizeof() failed")
}

func (f Fd) File() *os.File {
	return os.NewFile(uintptr(f), "")
}
