// +build amd64
// +build darwin

package native

import (
	"syscall"
)

func NativeToLinuxStatfs_t(s *syscall.Statfs_t) *LinuxStatfs_t {
	return &LinuxStatfs_t{
		Type:   int64(s.Type),
		Bsize:  int64(s.Bsize),
		Blocks: uint64(s.Blocks),
		Bfree:  uint64(s.Bfree),
		Bavail: uint64(s.Bavail),
		Files:  uint64(s.Files),
		Ffree:  uint64(s.Ffree),
		Fsid:   s.Fsid,
		// MAXPATH on 64-bit Darwin is 1024
		Namelen: 1024,
		// FIXME: unknown
		// Frsize:  s.Frsize,
		// FIXME: flags are almost certainly wrong
		Flags: int64(s.Flags),
	}
}

func copyIntToByteSlice(dst []byte, src []int8) {
	length := len(dst)
	if len(src) < len(dst) {
		length = len(src)
	}
	for i := 0; i < length; i++ {
		dst[i] = byte(src[i])
	}
}

func NativeToDarwinStatfs32_t(s *syscall.Statfs_t) *DarwinStatfs32_t {
	ret := &DarwinStatfs32_t{
		Bsize:  int(s.Bsize),
		Iosize: int(s.Iosize),
		Blocks: int(s.Blocks),
		Bfree:  int(s.Bfree),
		Bavail: int(s.Bavail),
		Files:  int(s.Files),
		Ffree:  int(s.Ffree),
		Fsid:   s.Fsid,
		// FIXME: type is truncated, maybe pick a default type
		Type:  int16(s.Type),
		Flags: int32(s.Flags),
	}
	copyIntToByteSlice(ret.Fstypename[:], s.Fstypename[:])
	copyIntToByteSlice(ret.Mntonname[:], s.Mntonname[:])
	copyIntToByteSlice(ret.Mntfromname[:], s.Mntfromname[:])
	return ret
}

func NativeToDarwinStatfs64_t(s *syscall.Statfs_t) *DarwinStatfs64_t {
	ret := &DarwinStatfs64_t{
		Bsize:  uint32(s.Bsize),
		Iosize: int32(s.Iosize),
		Blocks: uint64(s.Blocks),
		Bfree:  uint64(s.Bfree),
		Bavail: uint64(s.Bavail),
		Files:  uint64(s.Files),
		Ffree:  uint64(s.Ffree),
		Fsid:   s.Fsid,
		Type:   uint32(s.Type),
		Flags:  uint32(s.Flags),
	}
	copyIntToByteSlice(ret.Fstypename[:], s.Fstypename[:])
	copyIntToByteSlice(ret.Mntonname[:], s.Mntonname[:])
	copyIntToByteSlice(ret.Mntfromname[:], s.Mntfromname[:])
	return ret
}
