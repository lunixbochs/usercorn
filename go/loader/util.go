package loader

import (
	"io"
)

func getMagic(r io.ReaderAt) []byte {
	ret := make([]byte, 4)
	r.ReadAt(ret, 0)
	return ret
}
