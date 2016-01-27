package native

import (
	"syscall"
)

type LinuxStatfs_t struct {
	Type    int64  `struc:"off_t"`
	Bsize   int64  `struc:"off_t"`
	Blocks  uint64 `struc:"size_t"`
	Bfree   uint64 `struc:"size_t"`
	Bavail  uint64 `struc:"size_t"`
	Files   uint64 `struc:"size_t"`
	Ffree   uint64 `struc:"size_t"`
	Fsid    syscall.Fsid
	Namelen int64
	// fragment size, whatever that is
	Frsize int64 `struc:"off_t"`
	// since linux 2.6
	Flags int64    `struc:"off_t"`
	Spare [5]int64 `struc:"off_t"`
}

type DarwinStatfs32_t struct {
	Otype       int16
	Oflags      int16
	Bsize       int
	Iosize      int
	Blocks      int
	Bfree       int
	Bavail      int
	Files       int
	Ffree       int
	Fsid        syscall.Fsid
	Owner       int
	Reserved1   int16
	Type        int16
	Flags       int32
	Reserved2   int32
	Fstypename  [13]byte
	Mntonname   [90]byte
	Mntfromname [90]byte
	Reserved3   byte
	Reserved4   [4]int
}

type DarwinStatfs64_t struct {
	Bsize       uint32
	Iosize      int32
	Blocks      uint64
	Bfree       uint64
	Bavail      uint64
	Files       uint64
	Ffree       uint64
	Fsid        syscall.Fsid
	Owner       int
	Type        uint32
	Flags       uint32
	Fssubtype   uint32
	Fstypename  [16]byte
	Mntonname   [1024]byte
	Mntfromname [1024]byte
	Reserved    [8]uint32
}
