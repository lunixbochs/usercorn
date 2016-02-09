package unpack

import (
	"syscall"

	"github.com/lunixbochs/usercorn/go/native/enum"
)

var fileModeMap = map[int]int{
	00:       syscall.O_RDONLY,
	01:       syscall.O_WRONLY,
	02:       syscall.O_RDWR,
	0100:     syscall.O_CREAT,
	0200:     syscall.O_EXCL,
	0400:     syscall.O_NOCTTY,
	01000:    syscall.O_TRUNC,
	02000:    syscall.O_APPEND,
	04000:    syscall.O_NONBLOCK,
	010000:   syscall.O_DSYNC,
	04010000: syscall.O_SYNC,
	0200000:  syscall.O_DIRECTORY,
	0400000:  syscall.O_NOFOLLOW,
	02000000: syscall.O_CLOEXEC,
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
