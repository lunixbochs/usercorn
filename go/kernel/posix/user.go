package posix

import (
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *PosixKernel) Getegid() int {
	return os.Getegid()
}

func (k *PosixKernel) Getgid() int {
	return os.Getgid()
}

func (k *PosixKernel) Geteuid() int {
	return os.Geteuid()
}

func (k *PosixKernel) Getuid() int {
	return os.Getuid()
}

func (k *PosixKernel) Setgid(gid int) int {
	// TODO: doesn't work on Linux
	syscall.Setgid(gid)
	return 0
}

func (k *PosixKernel) Setuid(uid int) int {
	// TODO: doesn't work on Linux
	syscall.Setuid(uid)
	return 0
}

func (k *PosixKernel) Getgroups(count int, buf co.Buf) uint64 {
	groups, err := syscall.Getgroups()
	if err != nil {
		return Errno(err)
	}
	length := uint64(len(groups))
	if count > 0 {
		if count < len(groups) {
			groups = groups[:count]
		}
		tmp := make([]uint32, len(groups))
		for i, v := range groups {
			tmp[i] = uint32(v)
		}
		if err := buf.Pack(tmp); err != nil {
			return UINT64_MAX // FIXME
		}
	}
	return length
}
