package unpack

import (
	"bytes"
	"fmt"
	"syscall"
)

func sockaddrToNative(a interface{}) syscall.Sockaddr {
	switch v := a.(type) {
	case *SockaddrUnix:
		paths := bytes.SplitN(v.Path[:], []byte{0}, 2)
		return &syscall.SockaddrUnix{Name: string(paths[0])}
	case *SockaddrInet4:
		return &syscall.SockaddrInet4{Port: int(v.Port), Addr: v.Addr}
	case *SockaddrInet6:
		return &syscall.SockaddrInet6{Port: int(v.Port), Addr: v.Addr}
	case SockaddrLinklayer:
		return &syscall.SockaddrLinklayer{
			Protocol: v.Protocol, Ifindex: int(v.Ifindex), Hatype: v.Hatype,
			Pkttype: v.Pkttype, Halen: v.Halen,
		}
	case SockaddrNetlink:
		return &syscall.SockaddrNetlink{Pad: v.Pad, Pid: v.Pid, Groups: v.Groups}
	default:
		panic(fmt.Sprintf("sockAddrToNative unsupported type %T", v))
	}
}
