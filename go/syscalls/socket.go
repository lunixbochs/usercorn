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
		var addr RawSockaddrUnix
		struc.Unpack(buf, &addr)
		paths := bytes.SplitN([]byte(addr.Path[:]), []byte{0}, 2)
		return &syscall.SockaddrUnix{Name: string(paths[0])}
	case AF_INET:
		var addr syscall.RawSockaddrInet4
		struc.Unpack(buf, &addr)
		// TODO: unfinished
		return &syscall.SockaddrInet4{}
	}
	return nil
}
