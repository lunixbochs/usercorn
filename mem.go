package main

const (
	BASE         = 1024 * 1024
	UC_MEM_ALIGN = 8 * 1024
	STACK_BASE   = 0x7fff000
	STACK_SIZE   = 8 * 1024 * 1024
)

type mmap struct {
	Start, Size uint64
}

func align(addr, size uint64, growl ...bool) (uint64, uint64) {
	to := uint64(UC_MEM_ALIGN)
	right := addr + size
	right = ((right + to - 1) & ^to)
	addr &= ^(to - 1)
	size = right - addr
	if len(growl) > 0 && growl[0] {
		size = (size + (to - 1)) & (^(to - 1))
	}
	return addr, size
}
