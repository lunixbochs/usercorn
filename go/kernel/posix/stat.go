package posix

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
	Dev			int32			/* [XSI] ID of device containing file */
	Mode		uint16			/* [XSI] Mode of file (see below) */
	Nlink		uint16			/* [XSI] Number of hard links */
	Ino			uint64			/* [XSI] File serial number */
	Uid			uint32			/* [XSI] User ID of the file */
	Gid			uint32			/* [XSI] Group ID of the file */
	Rdev		int32			/* [XSI] Device ID */
	Pad0		int32			/* padding to align the embedded structs */
	
	Atime			int64	/* time of last access */
	AtimeNsec		int64	/* time of last access */
	Mtime			int64	/* time of last data modification */
	MtimeNsec		int64	/* time of last data modification */
	Ctime			int64	/* time of last status change */
	CtimeNsec		int64	/* time of last status change */
	Birthtime		int64	/* time of file creation(birth) */
	BirthtimeNsec	int64	/* time of file creation(birth) */
	
	Size 		int64			/* [XSI] file size, in bytes */
	Blkcnt		int64			/* [XSI] blocks allocated for file */
	Blksize		int32			/* [XSI] optimal blocksize for I/O */
	st_flags	uint32			/* user defined flags for file */
	st_gen 		uint32			/* file generation number */
	st_lspare	int32			/* RESERVED: DO NOT USE! */
	st_qspare	[2]int64		/* RESERVED: DO NOT USE! */
}
