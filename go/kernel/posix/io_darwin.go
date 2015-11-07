package posix

import (
	"bytes"
	"path/filepath"
	"syscall"
	"unsafe"
)

func PathFromFd(dirfd int) (string, error) {
	// FIXME? MAXPATHLEN on OS X is currently 1024
	buf := make([]byte, 1024)
	_, _, errn := syscall.Syscall(syscall.SYS_FCNTL, uintptr(dirfd), uintptr(syscall.F_GETPATH), uintptr(unsafe.Pointer(&buf[0])))
	if errn != 0 {
		return "", errn
	}
	tmp := bytes.SplitN(buf, []byte{0}, 2)
	return string(tmp[0]), nil
}

func openat_native(dirfd int, path string, flags int, mode uint32) uint64 {
	dirPath, _ := PathFromFd(dirfd)
	path = filepath.Join(dirPath, path)
	fd, err := syscall.Open(path, flags, mode)
	if err != nil {
		return Errno(err)
	}
	return uint64(fd)
}
