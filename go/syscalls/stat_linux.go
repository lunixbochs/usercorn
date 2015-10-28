package syscalls

// TODO: use FileInfo instead of nonportable Syscall interface?
import (
	"syscall"
)

func NewLinuxStat(stat *syscall.Stat_t, bits uint) interface{} {
	if bits == 64 {
		return &LinuxStat64{
			Dev:     uint64(stat.Dev),
			Ino:     stat.Ino,
			Mode:    uint32(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint64(stat.Rdev),
			Size:    stat.Size,
			Blksize: int64(stat.Blksize),
			// Blkcnt:  stat.Blkcnt,
			Atime: Timespec64{stat.Atim.Sec, stat.Atim.Nsec},
			Mtime: Timespec64{stat.Mtim.Sec, stat.Mtim.Nsec},
			Ctime: Timespec64{stat.Ctim.Sec, stat.Ctim.Nsec},
		}
	} else {
		return &LinuxStat{
			Dev:     uint64(stat.Dev),
			Ino:     uint32(stat.Ino),
			Mode:    uint32(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint64(stat.Rdev),
			Size:    stat.Size,
			Blksize: int32(stat.Blksize),
			// Blkcnt:  stat.Blkcnt,
			Atime: Timespec64{stat.Atim.Sec, stat.Atim.Nsec},
			Mtime: Timespec64{stat.Mtim.Sec, stat.Mtim.Nsec},
			Ctime: Timespec64{stat.Ctim.Sec, stat.Ctim.Nsec},
		}
	}
}

func NewDarwinStat(stat *syscall.Stat_t, bits uint) interface{} {
	panic("darwin stat struct unimplemented")
	return nil
}
