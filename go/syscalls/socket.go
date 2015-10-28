package syscalls

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
