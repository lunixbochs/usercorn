package syscalls

import (
	"syscalls"
)

func openat_native(dirfd int, path string, flags int, mode uint32) uint64 {
	fd, err := syscalls.Openat(dirfd, path, flags, mode)
	if err != nil {
		return errno(err)
	}
	return uint64(fd)
}
