package linux

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
)

const (
	SS_ONSTACK = 1
	SS_DISABLE = 2
	SS_AUTODISARM = 1 << 31
	SS_FLAG_BITS = SS_AUTODISARM
)

func (k *LinuxKernel) Sigaltstack(nss common.Buf, oss common.Obuf) uint64 {
	//TODO: track the flags properly
	if oss.Addr != 0 {
		oss.Pack(&k.CurrentStack)
	}
	if nss.Addr != 0 {
		if err := nss.Unpack(&k.CurrentStack); err != nil {
			return 1
		}
	}
	return 0
}
