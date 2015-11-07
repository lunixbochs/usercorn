package posix

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

type Iovec32 struct {
	Base uint32
	Len  uint32
}

type Iovec64 struct {
	Base uint64
	Len  uint64
}

func iovecIter(stream co.Buf, count uint64, bits uint) <-chan Iovec64 {
	ret := make(chan Iovec64)
	go func() {
		for i := uint64(0); i < count; i++ {
			if bits == 64 {
				var iovec Iovec64
				stream.Unpack(&iovec)
				ret <- iovec
			} else {
				var iv32 Iovec32
				stream.Unpack(&iv32)
				ret <- Iovec64{uint64(iv32.Base), uint64(iv32.Len)}
			}
		}
		close(ret)
	}()
	return ret
}
