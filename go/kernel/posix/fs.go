package posix

import (
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *PosixKernel) Statfs(path string, statfs co.Obuf) uint64 {
	var tmp syscall.Statfs_t
	if err := syscall.Statfs(path, &tmp); err != nil {
		return Errno(err)
	}
	if err := statfs.Pack(&tmp); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Fstatfs(fd co.Fd, statfs co.Obuf) uint64 {
	var tmp syscall.Statfs_t
	if err := syscall.Fstatfs(int(fd), &tmp); err != nil {
		return Errno(err)
	}
	if err := statfs.Pack(&tmp); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}
