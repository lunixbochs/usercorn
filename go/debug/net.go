package debug

import (
	"fmt"
	"net"
	"os"
)

func Accept(host, port string) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)
	fmt.Fprintf(os.Stderr, "Waiting for connection on %s\n", addr)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.Accept()
}
