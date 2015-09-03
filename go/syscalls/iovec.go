package syscalls

import (
	"encoding/binary"
	"github.com/lunixbochs/struc"
	"io"
)

type Iovec32 struct {
	Base uint32
	Len  uint32
}

type Iovec64 struct {
	Base uint64
	Len  uint64
}

func iovecIter(r io.Reader, count uint64, bits int, endian binary.ByteOrder) <-chan Iovec64 {
	ret := make(chan Iovec64)
	go func() {
		for i := uint64(0); i < count; i++ {
			if bits == 64 {
				var iovec Iovec64
				struc.UnpackWithOrder(r, &iovec, endian)
				ret <- iovec
			} else {
				var iv32 Iovec32
				struc.UnpackWithOrder(r, &iv32, endian)
				ret <- Iovec64{uint64(iv32.Base), uint64(iv32.Len)}
			}
		}
		close(ret)
	}()
	return ret
}
