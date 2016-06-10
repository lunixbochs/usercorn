package debug

import (
	"fmt"
	"github.com/lunixbochs/readline"
	"net"
	"os"

	"github.com/lunixbochs/usercorn/go/debug/cmd"
	"github.com/lunixbochs/usercorn/go/models"
)

type Debugger struct {
	instances []models.Usercorn
}

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

func NewDebugger(first models.Usercorn, extra ...models.Usercorn) *Debugger {
	instances := append([]models.Usercorn{first}, extra...)
	return &Debugger{instances}
}

func (d *Debugger) Run(c net.Conn) {
	fmt.Fprintf(os.Stderr, "Debug connection from %s\n", c.RemoteAddr())

	stdin, err := c.(*net.TCPConn).File()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening 'stdin' for debugger: %v\n", err)
		return
	}
	rl, err := readline.NewEx(&readline.Config{
		Prompt: "> ",
		Stderr: c,
		Stdin:  stdin,
		Stdout: c,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening readline for debugger: %v\n", err)
		return
	}
	context := &cmd.Context{ReadWriter: c, U: d.instances[0]}
	for {
		line, err := rl.Readline()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error in readline: %v\n", err)
			break
		}
		if err := cmd.Run(context, line); err != nil {
			fmt.Fprintf(os.Stderr, "error in command: %v\n", err)
			break
		}
	}
	stdin.Close()
	c.Close()
}
