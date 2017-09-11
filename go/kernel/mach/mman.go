package mach

import (
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
)

func (k *MachKernel) KernelrpcMachVmAllocateTrap(target int, addrOut co.Obuf, size co.Len, flags int) uint64 {
	addr, err := k.U.Malloc(uint64(size))
	if err != nil {
		return posix.UINT64_MAX // FIXME
	}
	if err := addrOut.Pack(addr); err != nil {
		return posix.UINT64_MAX // FIXME
	}
	return 0
}

func (k *MachKernel) KernelrpcMachVmDeallocateTrap(target int, addr co.Buf, size co.Len) uint64 {
	//TODO: implement
	return 0
}

func (k *MachKernel) KernelrpcMachVmMapTrap(target_mask uint32, addrOut co.Obuf, size uint64, mask uint64, flags int64, cur_prot uint64) uint64 {
	//TODO: implement prot/flags handling
	addr, err := k.U.Malloc(uint64(size))
	if err != nil {
		return posix.UINT64_MAX // FIXME
	}
	if err := addrOut.Pack(addr); err != nil {
		return posix.UINT64_MAX // FIXME
	}
	return 0
}
