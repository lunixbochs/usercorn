package mach

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
)

func (k *MachKernel) MachVmAllocate(unk int, size co.Len, addrOut co.Buf) uint64 {
	addr, err := k.U.Mmap(0, uint64(size))
	if err != nil {
		return posix.UINT64_MAX // FIXME
	}
	var tmp [8]byte
	buf, _ := k.U.PackAddr(tmp[:], addr)
	if err := addrOut.Pack(buf); err != nil {
		return posix.UINT64_MAX // FIXME
	}
	return 0
}

func (k *MachKernel) MachVmDeallocate() {}
