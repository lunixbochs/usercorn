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
	Sec  uint32
	Nsec uint32
}

type Timespec64 struct {
	Sec  uint64
	Nsec uint64
}

// TODO: these might only work on x86
type LinuxStat struct {
	Dev      uint32
	Ino      uint32
	Mode     uint16
	Nlink    uint16
	Uid, Gid uint32
	Rdev     uint32
	Size     uint32
	Blksize  uint32
	Blkcnt   uint32

	Atime     uint32
	AtimeNsec uint32
	Mtime     uint32
	MtimeNsec uint32
	Ctime     uint32
	CtimeNsec uint32

	Reserved4 uint32
	Reserved5 uint32
}

type LinuxStat64 struct {
	Dev      uint64
	Ino      uint64
	Nlink    uint64
	Mode     uint32
	Uid, Gid uint32
	Pad0     uint32
	Rdev     uint64
	Size     int64
	Blksize  int64
	Blkcnt   int64

	Atime     uint64
	AtimeNsec uint64
	Mtime     uint64
	MtimeNsec uint64
	Ctime     uint64
	CtimeNsec uint64

	Reserved3 [3]uint64
}

type DarwinStat struct {
}

type DarwinStat64 struct {
}
