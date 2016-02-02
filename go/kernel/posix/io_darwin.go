package posix

import (
	"bytes"
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
