package syscalls

import "syscall"

func NewTargetStat(stat *syscall.Stat_t, os string, bits uint) interface{} {
	switch os {
	case "linux":
		return NewLinuxStat(stat, bits)
	case "darwin":
		return NewDarwinStat(stat, bits)
	default:
		panic("(currently) unsupported target OS for fstat: " + os)
	}
}

type Timespec struct {
	Sec  int64
	Nsec int64
}

type Timespec64 struct {
	Sec  int64
	Nsec int64
}

// TODO?: this assumes LARGEFILE
type LinuxStat struct {
	Dev       uint64
	Pad1      uint16
	Ino       uint32 // ulong
	Mode      uint32
	Nlink     uint32 // ulong
	Uid, Gid  uint32
	Rdev      uint64
	Pad2      uint16
	Size      int64
	Blksize   int32 // slong
	Blkcnt    int64
	Atime     Timespec64
	Mtime     Timespec64
	Ctime     Timespec64
	Reserved4 uint64
}

type LinuxStat64 struct {
	Dev       uint64
	Ino       uint64 // ulong
	Nlink     int64  // ulong
	Mode      uint32
	Uid, Gid  uint32
	Pad0      int
	Rdev      uint64
	Pad2      uint16
	Size      int64
	Blksize   int64 // slong
	Blkcnt    int64
	Atime     Timespec64
	Mtime     Timespec64
	Ctime     Timespec64
	Reserved3 [3]uint64
	Reserved4 uint64
}

type DarwinStat struct {
}

type DarwinStat64 struct {
}
