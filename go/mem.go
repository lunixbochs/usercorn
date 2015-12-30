package usercorn

const (
	BASE         = 1024 * 1024
	UC_MEM_ALIGN = 8 * 1024
	STACK_BASE   = 0x60000000
	STACK_SIZE   = 8 * 1024 * 1024
)

func align(addr, size uint64, growl ...bool) (uint64, uint64) {
	to := uint64(UC_MEM_ALIGN)
	mask := ^(to - 1)
	right := addr + size
	right = (right + to - 1) & mask
	addr &= mask
	size = right - addr
	if len(growl) > 0 && growl[0] {
		size = (size + to) & mask
	}
	return addr, size
}
