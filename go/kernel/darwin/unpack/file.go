package unpack

import (
	"syscall"

	"github.com/lunixbochs/usercorn/go/native/enum"
)

var fileModeMap = map[int]int{
	0x0:       syscall.O_RDONLY,
	0x1:       syscall.O_WRONLY,
	0x2:       syscall.O_RDWR,
	0x4:       syscall.O_NONBLOCK,
	0x8:       syscall.O_APPEND,
	0x80:      syscall.O_SYNC,
	0x100:     syscall.O_NOFOLLOW,
	0x400:     syscall.O_TRUNC,
	0x200:     syscall.O_CREAT,
	0x800:     syscall.O_EXCL,
	0x20000:   syscall.O_NOCTTY,
	0x100000:  syscall.O_DIRECTORY,
	0x400000:  syscall.O_DSYNC,
	0x1000000: syscall.O_CLOEXEC,

	// darwin-only?
	// 0x8000:   O_EVTONLY,
	// 0x200000: O_SYMLINK,
}

func OpenFlag(reg uint64) enum.OpenFlag {
	var out enum.OpenFlag
	for a, b := range fileModeMap {
		if int(reg)&a == a {
			out |= enum.OpenFlag(b)
		}
	}
	return out
}
