package posix

import (
	"syscall"
)

const UINT64_MAX = 0xFFFFFFFFFFFFFFFF

func Errno(err error) uint64 {
	if err != nil {
		return uint64(int64(-err.(syscall.Errno)))
	}
	return 0
}
