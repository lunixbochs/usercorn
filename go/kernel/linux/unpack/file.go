package unpack

import (
	"os"

	"github.com/lunixbochs/usercorn/go/native/enum"
)

const (
	O_RDONLY = 00
	O_WRONLY = 01
	O_RDWR   = 02

	O_CREAT     = 0100
	O_EXCL      = 0200
	O_NOCTTY    = 0400
	O_TRUNC     = 01000
	O_APPEND    = 02000
	O_NONBLOCK  = 04000
	O_DSYNC     = 010000
	O_SYNC      = 04010000
	O_RSYNC     = 04010000
	O_DIRECTORY = 0200000
	O_NOFOLLOW  = 0400000
	O_CLOEXEC   = 02000000
)

var fileModeMap = map[int]int{
	O_RDONLY: os.O_RDONLY,
	O_WRONLY: os.O_WRONLY,
	O_RDWR:   os.O_RDWR,
	O_APPEND: os.O_APPEND,
	O_CREAT:  os.O_CREATE,
	O_EXCL:   os.O_EXCL,
	O_SYNC:   os.O_SYNC,
	O_TRUNC:  os.O_TRUNC,
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
