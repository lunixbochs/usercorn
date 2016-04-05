package unpack

import (
	"syscall"
)

var mmapFlagMap = map[int]int{
	0x0: syscall.MAP_FILE,
	0x1: syscall.MAP_SHARED,
	0x2: syscall.MAP_PRIVATE,

	0x10:   syscall.MAP_FIXED,
	0x20:   syscall.MAP_RENAME,
	0x40:   syscall.MAP_NORESERVE,
	0x80:   syscall.MAP_RESERVED0080,
	0x100:  syscall.MAP_NOEXTEND,
	0x200:  syscall.MAP_HASSEMAPHORE,
	0x400:  syscall.MAP_NOCACHE,
	0x800:  syscall.MAP_JIT,
	0x1000: syscall.MAP_ANON,
}
