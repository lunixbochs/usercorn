package posix

import (
	"fmt"
	"io/ioutil"
	"syscall"
)

func PathFromFd(dirfd int) (string, error) {
	p, err := ioutil.ReadFile(fmt.Sprintf("/proc/self/fd/%d", dirfd))
	return string(p), err
}

func openat_native(dirfd int, path string, flags int, mode uint32) uint64 {
	fd, err := syscall.Openat(dirfd, path, flags, mode)
	if err != nil {
		return Errno(err)
	}
	return uint64(fd)
}
