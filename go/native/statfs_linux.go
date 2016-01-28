package native

import (
	"syscall"
)

func StatfsToLinux(s *syscall.Statfs_t) *LinuxStatfs_t {
	return &LinuxStatfs_t{
		Type:    int64(s.Type),
		Bsize:   int64(s.Bsize),
		Blocks:  s.Blocks,
		Bfree:   s.Bfree,
		Bavail:  s.Bavail,
		Files:   s.Files,
		Ffree:   s.Ffree,
		Fsid:    s.Fsid,
		Namelen: int64(s.Namelen),
		Frsize:  int64(s.Frsize),
		Flags:   int64(s.Flags),
	}
}

func StatfsToDarwin32(s *syscall.Statfs_t) *DarwinStatfs32_t {
	// TODO: fs type, owner, mnt names?
	return &DarwinStatfs32_t{
		Bsize:  int(s.Bsize),
		Blocks: int(s.Blocks),
		Bfree:  int(s.Bfree),
		Bavail: int(s.Bavail),
		Files:  int(s.Files),
		Ffree:  int(s.Ffree),
		Fsid:   s.Fsid,
	}
}

func StatfsToDarwin64(s *syscall.Statfs_t) *DarwinStatfs64_t {
	// TODO: fs type, owner, mnt names?
	return &DarwinStatfs64_t{
		Bsize:  uint32(s.Bsize),
		Blocks: uint64(s.Blocks),
		Bfree:  uint64(s.Bfree),
		Bavail: uint64(s.Bavail),
		Files:  uint64(s.Files),
		Ffree:  uint64(s.Ffree),
		Fsid:   s.Fsid,
	}
}
