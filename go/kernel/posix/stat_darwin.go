package posix

// TODO: use FileInfo instead of nonportable Syscall interface?
import (
	"syscall"
)

func NewLinuxStat_generic(stat *syscall.Stat_t, bits uint, large bool) interface{} {
	return &LinuxStat_generic{
		Dev:       uint32(stat.Dev),
		Ino:       uint64(stat.Ino),
		Mode:      uint32(stat.Mode),
		Uid:       stat.Uid,
		Gid:       stat.Gid,
		Rdev:      uint32(stat.Rdev),
		Size:      int64(stat.Size),
		Blksize:   uint32(stat.Blksize),
		Blkcnt:    uint64(stat.Blocks),
		Atime:     uint32(stat.Atimespec.Sec),
		AtimeNsec: uint32(stat.Atimespec.Nsec),
		Mtime:     uint32(stat.Mtimespec.Sec),
		MtimeNsec: uint32(stat.Mtimespec.Nsec),
		Ctime:     uint32(stat.Ctimespec.Sec),
		CtimeNsec: uint32(stat.Ctimespec.Nsec),
	}
}

func NewLinuxStat_x86(stat *syscall.Stat_t, bits uint, large bool) interface{} {
	if bits == 64 {
		return &LinuxStat64_x86{
			Dev:       uint64(stat.Dev),
			Ino:       uint64(stat.Ino),
			Mode:      uint32(stat.Mode),
			Uid:       stat.Uid,
			Gid:       stat.Gid,
			Rdev:      uint64(stat.Rdev),
			Size:      int64(stat.Size),
			Blksize:   int64(stat.Blksize),
			Blkcnt:    int64(stat.Blocks),
			Atime:     uint64(stat.Atimespec.Sec),
			AtimeNsec: uint64(stat.Atimespec.Nsec),
			Mtime:     uint64(stat.Mtimespec.Sec),
			MtimeNsec: uint64(stat.Mtimespec.Nsec),
			Ctime:     uint64(stat.Ctimespec.Sec),
			CtimeNsec: uint64(stat.Ctimespec.Nsec),
		}
	} else {
		if large {
			return &Linux32Stat64_x86{
				Dev:       uint64(stat.Dev),
				Ino:       uint32(stat.Ino),
				Mode:      uint32(stat.Mode),
				Uid:       stat.Uid,
				Gid:       stat.Gid,
				Rdev:      uint64(stat.Rdev),
				Size:      int64(stat.Size),
				Blksize:   uint32(stat.Blksize),
				Blkcnt:    uint64(stat.Blocks),
				Atime:     uint32(stat.Atimespec.Sec),
				AtimeNsec: uint32(stat.Atimespec.Nsec),
				Mtime:     uint32(stat.Mtimespec.Sec),
				MtimeNsec: uint32(stat.Mtimespec.Nsec),
				Ctime:     uint32(stat.Ctimespec.Sec),
				CtimeNsec: uint32(stat.Ctimespec.Nsec),
				LongIno:   uint64(stat.Ino),
			}
		}
		return &Linux32Stat_x86{
			Dev:       uint32(stat.Dev),
			Ino:       uint32(stat.Ino),
			Mode:      uint16(stat.Mode),
			Uid:       stat.Uid,
			Gid:       stat.Gid,
			Rdev:      uint32(stat.Rdev),
			Size:      uint32(stat.Size),
			Blksize:   uint32(stat.Blksize),
			Blkcnt:    uint32(stat.Blocks),
			Atime:     uint32(stat.Atimespec.Sec),
			AtimeNsec: uint32(stat.Atimespec.Nsec),
			Mtime:     uint32(stat.Mtimespec.Sec),
			MtimeNsec: uint32(stat.Mtimespec.Nsec),
			Ctime:     uint32(stat.Ctimespec.Sec),
			CtimeNsec: uint32(stat.Ctimespec.Nsec),
		}
	}
}

func NewDarwinStat(stat *syscall.Stat_t, bits uint, large bool) interface{} {
	if bits == 64 {
		return &DarwinStat64{
			Dev:       int32(stat.Dev),
			Mode:      uint16(stat.Mode),
			Ino:       uint64(stat.Ino),
			Uid:       uint32(stat.Uid),
			Gid:       uint32(stat.Gid),
			Rdev:      int32(stat.Rdev),
			Size:      int64(stat.Size),
			Blksize:   int32(stat.Blksize),
			Blkcnt:    int64(stat.Blocks),
			Atime:     int64(stat.Atimespec.Sec),
			AtimeNsec: int64(stat.Atimespec.Nsec),
			Mtime:     int64(stat.Mtimespec.Sec),
			MtimeNsec: int64(stat.Mtimespec.Nsec),
			Ctime:     int64(stat.Ctimespec.Sec),
			CtimeNsec: int64(stat.Ctimespec.Nsec),
		}
	} else {
		panic("darwin-32 stat struct unimplemented")
	}
}
