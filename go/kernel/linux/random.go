package linux

import (
	"crypto/rand"
	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *LinuxKernel) Getrandom(buf co.Obuf, size uint64, flags uint32) uint64 {
	tmp := make([]byte, size)
	n, _ := rand.Read(tmp)
	tmp = tmp[:n]
	if err := buf.Pack(tmp); err != nil {
		return UINT64_MAX
	}
	return uint64(n)
}

