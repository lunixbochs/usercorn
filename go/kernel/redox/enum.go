package redox

// these numbers are from https://github.com/redox-os/redox/blob/master/crates/system/syscall/unix.rs
var RedoxSysNum = map[int]string{
	1:   "exit",
	3:   "read",
	4:   "write",
	5:   "open",
	6:   "close",
	7:   "waitpid",
	9:   "link",
	10:  "unlink",
	11:  "execve",
	12:  "chdir",
	18:  "stat",
	19:  "lseek",
	20:  "getpid",
	28:  "fstat",
	39:  "mkdir",
	41:  "dup",
	45:  "brk",
	84:  "rmdir",
	93:  "ftruncate",
	118: "fsync",
	120: "clone",
	158: "yield",
	162: "nanosleep",
	265: "clock_gettime",
	331: "pipe2",
	928: "fpath",
}

const (
	CLONE_VM    = 0x100
	CLONE_FS    = 0x200
	CLONE_FILES = 0x400
	CLONE_VFORK = 0x4000

	CLOCK_REALTIME  = 1
	CLOCK_MONOTONIC = 4

	SEEK_SET = 0
	SEEK_CUR = 1
	SEEK_END = 2

	O_RDONLY   = 0
	O_WRONLY   = 1
	O_RDWR     = 2
	O_NONBLOCK = 4
	O_APPEND   = 8
	O_SHLOCK   = 0x10
	O_EXLOCK   = 0x20
	O_ASYNC    = 0x40
	O_FSYNC    = 0x80
	O_CREAT    = 0x200
	O_TRUNC    = 0x400
	O_EXCL     = 0x800

	MODE_DIR  = 0x4000
	MODE_FILE = 0x8000
)
