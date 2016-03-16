package unpack

import "syscall"

var mmapFlagMap = map[int]int{
	0x0: syscall.MAP_FILE,
	0x1: syscall.MAP_SHARED,
	0x2: syscall.MAP_PRIVATE,

	0x10:    syscall.MAP_FIXED,
	0x20:    syscall.MAP_ANON,
	0x4000:  syscall.MAP_NORESERVE,
	0x0100:  syscall.MAP_GROWSDOWN,
	0x0800:  syscall.MAP_DENYWRITE,
	0x1000:  syscall.MAP_EXECUTABLE,
	0x2000:  syscall.MAP_LOCKED,
	0x8000:  syscall.MAP_POPULATE,
	0x10000: syscall.MAP_NONBLOCK,
}
