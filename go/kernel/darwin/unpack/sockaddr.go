package unpack

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/lunixbochs/usercorn/go/kernel/common"
)

const (
	AF_LOCAL  = 1
	AF_INET   = 2
	AF_INET6  = 30
	AF_PACKET = 18
)

type SockaddrHeader struct {
	Length uint8
	Family uint8
}

type SockaddrInet4 struct {
	Header SockaddrHeader
	Port   uint16
	Addr   [4]byte
}

type SockaddrInet6 struct {
	Header   SockaddrHeader
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	Scope_id uint32
}

type SockaddrLinklayer struct {
	Header   SockaddrHeader
	Protocol uint16
	Ifindex  int32
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
	Addr     [8]uint8
}

type SockaddrUnix struct {
	Header SockaddrHeader
	Path   [108]byte
}

func Sockaddr(buf common.Buf, length int) syscall.Sockaddr {
	var port [2]byte
	order := buf.K.U.ByteOrder()
	// TODO: handle insufficient length
	var header SockaddrHeader
	if err := buf.Unpack(&header); err != nil {
		fmt.Println("unpack error", err)
		panic("sockaddr unpack error")
		return nil
	}
	// TODO: handle errors?
	st := buf.Struc()
	switch header.Family {
	case AF_LOCAL:
		var a SockaddrUnix
		st.Unpack(&a)
		return sockaddrToNative(&a)
	case AF_INET:
		var a SockaddrInet4
		st.Unpack(&a)
		order.PutUint16(port[:], a.Port)
		a.Port = binary.BigEndian.Uint16(port[:])
		return sockaddrToNative(&a)
	case AF_INET6:
		var a SockaddrInet6
		st.Unpack(&a)
		order.PutUint16(port[:], a.Port)
		a.Port = binary.BigEndian.Uint16(port[:])
		return sockaddrToNative(&a)
	case AF_PACKET:
		var a SockaddrLinklayer
		st.Unpack(&a)
		return sockaddrToNative(&a)
	default:
		fmt.Println("AF not known", header.Family)
		panic("unknown socket address family")
	}
	return nil
}
