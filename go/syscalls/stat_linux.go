package syscalls

// TODO: use FileInfo instead of nonportable Syscall interface?
import (
	"syscall"
)

func NewLinuxStat(stat *syscall.Stat_t, bits uint) interface{} {
	if bits == 64 {
		return &LinuxStat64{
			Dev:     uint64(stat.Dev),
			Ino:     uint64(stat.Ino),
			Mode:    uint32(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint64(stat.Rdev),
			Size:    int64(stat.Size),
			Blksize: int64(stat.Blksize),
			// Blkcnt:  stat.Blkcnt,
			Atime: Timespec64{int64(stat.Atim.Sec), int64(stat.Atim.Nsec)},
			Mtime: Timespec64{int64(stat.Mtim.Sec), int64(stat.Mtim.Nsec)},
			Ctime: Timespec64{int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)},
		}
	} else {
		return &LinuxStat{
			Dev:     uint64(stat.Dev),
			Ino:     uint32(stat.Ino),
			Mode:    uint32(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint64(stat.Rdev),
			Size:    int32(stat.Size),
			Blksize: int32(stat.Blksize),
			// Blkcnt:  stat.Blkcnt,
			Atime: Timespec{int32(stat.Atim.Sec), int32(stat.Atim.Nsec)},
			Mtime: Timespec{int32(stat.Mtim.Sec), int32(stat.Mtim.Nsec)},
			Ctime: Timespec{int32(stat.Ctim.Sec), int32(stat.Ctim.Nsec)},
		}
	}
}

func NewDarwinStat(stat *syscall.Stat_t, bits uint) interface{} {
	panic("darwin stat struct unimplemented")
	return nil
}
