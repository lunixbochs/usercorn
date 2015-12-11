package posix

import (
	"fmt"
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/native"
)

func (k *PosixKernel) Socket(domain, typ, protocol int) uint64 {
	fd, err := syscall.Socket(domain, typ, protocol)
	if err != nil {
		return Errno(err)
	}
	return uint64(fd)
}

func (k *PosixKernel) Connect(fd co.Fd, sa syscall.Sockaddr, size co.Len) uint64 {
	return Errno(syscall.Connect(int(fd), sa))
}

func (k *PosixKernel) Bind(fd co.Fd, sa syscall.Sockaddr, size co.Len) uint64 {
	return Errno(syscall.Bind(int(fd), sa))
}

func (k *PosixKernel) Sendto(fd co.Fd, buf co.Buf, size co.Len, flags int, sa syscall.Sockaddr, socklen co.Len) uint64 {
	msg := make([]byte, size)
	if err := buf.Unpack(msg); err != nil {
		return UINT64_MAX // FIXME
	}
	return Errno(syscall.Sendto(int(fd), msg, flags, sa))
}

func (k *PosixKernel) Recvfrom(fd co.Fd, buf co.Buf, size co.Len, flags int, from co.Buf, fromlen co.Len) uint64 {
	p := make([]byte, size)
	if n, _, err := syscall.Recvfrom(int(fd), p, flags); err != nil {
		// TODO: need kernel.Pack() so we can pack a sockaddr into from
		buf.Pack(p)
		return uint64(n)
	} else {
		return UINT64_MAX // FIXME
	}
}

func (k *PosixKernel) Getsockopt(fd co.Fd, level, opt int, valueOut, valueSizeOut co.Buf) uint64 {
	// TODO: dispatch/support both addr and int types
	value, err := syscall.GetsockoptInt(int(fd), level, opt)
	if err != nil {
		return Errno(err)
	}
	value32 := int32(value)
	size := int32(4)
	if err := valueOut.Pack(value32); err != nil {
		return UINT64_MAX // FIXME
	}
	if err := valueSizeOut.Pack(size); err != nil {
		return UINT64_MAX // FIXME
	}
	return 0
}

func (k *PosixKernel) Setsockopt(fd co.Fd, level, opt int, valueIn co.Buf, size int) uint64 {
	// TODO: dispatch/support all setsockopt types
	if size != 4 {
		fmt.Fprintf(os.Stderr, "WARNING: unsupported Setsockopt type %d\n", size)
		return UINT64_MAX // FIXME
	}
	var value int32
	if err := valueIn.Unpack(&value); err != nil {
		return UINT64_MAX // FIXME
	}
	if err := syscall.SetsockoptInt(int(fd), level, opt, opt); err != nil {
		return Errno(err)
	}
	return 0
}

func getfdset(b co.Buf) (*syscall.FdSet, error) {
	if b.Addr == 0 {
		return nil, nil
	}
	fdset := &native.Fdset32{}
	err := b.Unpack(fdset)
	return fdset.Native(), err
}

func putfdset(b co.Buf, fdset *syscall.FdSet) error {
	if fdset != nil && b.Addr != 0 {
		return b.Copy().Pack(fdset)
	}
	return nil
}

func (k *PosixKernel) Select(nfds int, readfds, writefds, errorfds co.Buf, timeout *syscall.Timeval) uint64 {
	// TODO: might need to tweak 64-bit little-endian fdset parsing
	r, err := getfdset(readfds)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	w, err := getfdset(writefds)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	e, err := getfdset(errorfds)
	if err != nil {
		return UINT64_MAX // FIXME
	}
	if err := nativeSelect(nfds, r, w, e, timeout); err != nil {
		return Errno(err)
	}
	// write out fdsets
	putfdset(readfds, r)
	putfdset(writefds, w)
	putfdset(errorfds, e)
	return 0
}
