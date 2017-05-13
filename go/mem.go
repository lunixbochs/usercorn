package usercorn

const (
	BASE         = 0x100000
	UC_MEM_ALIGN = 0x1000
)

func align(addr, size uint64, growl ...bool) (uint64, uint64) {
	to := uint64(UC_MEM_ALIGN)
	mask := ^(to - 1)
	right := addr + size
	right = (right + to - 1) & mask
	addr &= mask
	size = right - addr
	if len(growl) > 0 && growl[0] {
		size = (size + to - 1) & mask
	}
	return addr, size
}
