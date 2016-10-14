package mach

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
)

func (k *MachKernel) KernelrpcMachVmAllocateTrap(target int, addrOut co.Obuf, size co.Len, flags int) uint64 {
	mmap, err := k.U.Mmap(0, uint64(size))
	if err != nil {
		return posix.UINT64_MAX // FIXME
	}
	var tmp [8]byte
	buf, _ := k.U.PackAddr(tmp[:], mmap.Addr)
	if err := addrOut.Pack(buf); err != nil {
		return posix.UINT64_MAX // FIXME
	}
	return 0
}

func (k *MachKernel) KernelrpcMachVmDeallocateTrap(target int, addr co.Buf, size co.Len) uint64 {
	//TODO: implement
	return 0
}

func (k *MachKernel) KernelrpcMachVmMapTrap(target_mask uint32, addr co.Buf, size uint64, mask uint64, flags int64, cur_prot uint64) uint64 {
	//TODO: implement prot/flags handling
	mmap, err := k.U.Mmap(0, uint64(size))
	if err != nil {
		return posix.UINT64_MAX // FIXME
	}
	var tmp [8]byte
	buf, _ := k.U.PackAddr(tmp[:], mmap.Addr)
	if err := addr.Pack(buf); err != nil {
		return posix.UINT64_MAX // FIXME
	}
	return 0
}
