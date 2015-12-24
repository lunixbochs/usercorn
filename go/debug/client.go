package debug

import (
	"fmt"
	"github.com/lunixbochs/readline"
	"io"
	"net"
	"os"
)

// like go io.Copy(), but returns a channel to notify you upon completion
func copyNotify(dst io.Writer, src io.Reader) chan int {
	ret := make(chan int)
	go func() {
		io.Copy(dst, src)
		ret <- 1
	}()
	return ret
}

func RunClient(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("error connecting to debug server: %v", err)
	}
	_, err = readline.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("error placing stdin into raw mode: %v", err)
	}
	remoteEOF := copyNotify(os.Stdout, conn)
	localEOF := copyNotify(conn, os.Stdin)
	select {
	case <-remoteEOF:
		return fmt.Errorf("remote closed connection")
	case <-localEOF:
		return nil
	}
}
