package debug

import (
	"github.com/lunixbochs/readline"
	"github.com/pkg/errors"
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
	stdinFd := int(os.Stdin.Fd())
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return errors.Errorf("error connecting to debug server: %v", err)
	}
	termState, err := readline.MakeRaw(stdinFd)
	if err != nil {
		return errors.Errorf("error placing stdin into raw mode: %v", err)
	}
	// defer to ensure original stdin isn't left in raw mode
	defer func() {
		err := recover()
		readline.Restore(stdinFd, termState)
		if err != nil {
			panic(err)
		}
	}()

	remoteEOF := copyNotify(os.Stdout, conn)
	localEOF := copyNotify(conn, os.Stdin)
	select {
	case <-remoteEOF:
		return errors.Errorf("remote closed connection")
	case <-localEOF:
		return nil
	}
}
