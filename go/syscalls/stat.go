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
	Sec  int32
	Nsec int32
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
	Size      int32 // slong
	Blksize   int32 // slong
	Blkcnt    int32 // slong
	Atime     Timespec
	Mtime     Timespec
	Ctime     Timespec
	Reserved4 uint32
	Reserved5 uint32
}

type LinuxStat64 struct {
	Dev       uint64
	Ino       uint64 // ulong
	Nlink     uint64 // ulong
	Mode      uint32
	Uid, Gid  uint32
	Pad0      int32
	Rdev      uint64
	Size      int64 // slong
	Blksize   int64 // slong
	Blkcnt    int64 // slong
	Atime     Timespec64
	Mtime     Timespec64
	Ctime     Timespec64
	Reserved3 [3]uint64
}

type DarwinStat struct {
}

type DarwinStat64 struct {
}
