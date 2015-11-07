package posix

import (
	"bytes"
	"fmt"
	"github.com/lunixbochs/struc"
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

const (
	AF_LOCAL   = 1
	AF_INET    = 2
	AF_INET6   = 10
	AF_PACKET  = 17
	AF_NETLINK = 16
)

type RawSockaddrUnix struct {
	Family uint16
	Path   [108]byte
}

// TODO: needs to be target kernel specific (see #97)
func decodeSockaddr(u models.Usercorn, p []byte) syscall.Sockaddr {
	family := u.ByteOrder().Uint16(p)
	buf := bytes.NewReader(p)
	switch family {
	case AF_LOCAL:
		var a RawSockaddrUnix
		struc.UnpackWithOrder(buf, &a, u.ByteOrder())
		paths := bytes.SplitN([]byte(a.Path[:]), []byte{0}, 2)
		return &syscall.SockaddrUnix{Name: string(paths[0])}
	case AF_INET:
		var a syscall.RawSockaddrInet4
		struc.UnpackWithOrder(buf, &a, u.ByteOrder())
		return &syscall.SockaddrInet4{Port: int(a.Port), Addr: a.Addr}
	case AF_INET6:
		var a syscall.RawSockaddrInet6
		struc.UnpackWithOrder(buf, &a, u.ByteOrder())
		return &syscall.SockaddrInet6{Port: int(a.Port), Addr: a.Addr}
		// TODO: only on Linux?
		/*
			case AF_PACKET:
				var a syscall.RawSockaddrLinkLayer
				struc.UnpackWithOrder(buf, &a, u.ByteOrder())
				return &syscall.SockaddrLinkLayer{
					Protocol: a.Protocol, Ifindex: a.Ifindex, Hatype: a.Hatype,
					Pkttype: a.Pkttype, Halen: a.Halen,
				}
			case AF_NETLINK:
				var a syscall.RawSockaddrNetlink
				struc.UnpackWithOrder(buf, &a, u.ByteOrder())
				return &syscall.SockaddrNetlink{Pad: a.Pad, Pid: a.Pid, Groups: a.Groups}
		*/
	}
	return nil
}

func (k *Kernel) Socket(domain, typ, protocol int) uint64 {
	fd, err := syscall.Socket(domain, typ, protocol)
	if err != nil {
		return Errno(err)
	}
	return uint64(fd)
}

func (k *Kernel) Connect(fd co.Fd, buf co.Buf, size co.Len) uint64 {
	sockaddrbuf := make([]byte, size)
	if err := buf.Unpack(sockaddrbuf); err != nil {
		return UINT64_MAX // FIXME
	}
	sa := decodeSockaddr(k.U, sockaddrbuf)
	if sa == nil {
		return UINT64_MAX // FIXME
	}
	return Errno(syscall.Connect(int(fd), sa))
}

func (k *Kernel) Bind(fd co.Fd, buf co.Buf, size co.Len) uint64 {
	sockaddrbuf := make([]byte, size)
	if err := buf.Unpack(sockaddrbuf); err != nil {
		return UINT64_MAX // FIXME
	}
	sa := decodeSockaddr(k.U, sockaddrbuf)
	if sa == nil {
		return UINT64_MAX // FIXME
	}
	return Errno(syscall.Bind(int(fd), sa))
}

func (k *Kernel) Sendto(fd co.Fd, buf co.Buf, size co.Len, flags int, sockbuf co.Buf, socklen co.Len) uint64 {
	msg := make([]byte, size)
	if err := buf.Unpack(msg); err != nil {
		return UINT64_MAX // FIXME
	}
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{}
	if socklen > 0 {
		sockaddrbuf := make([]byte, socklen)
		if err := sockbuf.Unpack(sockaddrbuf); err != nil {
			return UINT64_MAX // FIXME
		}
		sa = decodeSockaddr(k.U, sockaddrbuf)
		if sa == nil {
			return UINT64_MAX // FIXME
		}
	}
	return Errno(syscall.Sendto(int(fd), msg, flags, sa))
}

func (k *Kernel) Getsockopt(fd co.Fd, level, opt int, valueOut, valueSizeOut co.Buf) uint64 {
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

func (k *Kernel) Setsockopt(fd co.Fd, level, opt int, valueIn co.Buf, size int) uint64 {
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
