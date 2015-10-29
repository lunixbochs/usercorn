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
			// Blkcnt:    stat.Blkcnt,
			Atime:     uint64(stat.Atim.Sec),
			AtimeNsec: uint64(stat.Atim.Nsec),
			Mtime:     uint64(stat.Mtim.Sec),
			MtimeNsec: uint64(stat.Mtim.Nsec),
			Ctime:     uint64(stat.Ctim.Sec),
			CtimeNsec: uint64(stat.Ctim.Nsec),
		}
	} else {
		return &LinuxStat{
			Dev:     uint32(stat.Dev),
			Ino:     uint32(stat.Ino),
			Mode:    uint16(stat.Mode),
			Uid:     stat.Uid,
			Gid:     stat.Gid,
			Rdev:    uint32(stat.Rdev),
			Size:    uint32(stat.Size),
			Blksize: uint32(stat.Blksize),
			// Blkcnt:    stat.Blkcnt,
			Atime:     uint32(stat.Atim.Sec),
			AtimeNsec: uint32(stat.Atim.Nsec),
			Mtime:     uint32(stat.Mtim.Sec),
			MtimeNsec: uint32(stat.Mtim.Nsec),
			Ctime:     uint32(stat.Ctim.Sec),
			CtimeNsec: uint32(stat.Ctim.Nsec),
		}
	}
}

func NewDarwinStat(stat *syscall.Stat_t, bits uint) interface{} {
	panic("darwin stat struct unimplemented")
	return nil
}
