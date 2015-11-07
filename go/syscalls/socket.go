package syscalls

import (
	"bytes"
	"github.com/lunixbochs/struc"
	"syscall"
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

func decodeSockaddr(u U, p []byte) syscall.Sockaddr {
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
