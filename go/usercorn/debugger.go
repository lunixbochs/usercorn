package main

import (
	"fmt"
	// uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"github.com/lunixbochs/readline"
	"net"
	"os"

	"github.com/lunixbochs/usercorn/go/models"
)

type Debugger struct {
	instances []models.Usercorn
}

func NewDebugger(first models.Usercorn, extra ...models.Usercorn) *Debugger {
	instances := append([]models.Usercorn{first}, extra...)
	return &Debugger{instances}
}

func (d *Debugger) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error in debug accept: %v", err)
				return
			}
			go d.Handle(conn)
		}
	}()
	return nil
}

func (d *Debugger) Handle(c net.Conn) {
	fmt.Fprintf(os.Stderr, "handling conn: %v\n", c)

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
	for {
		line, err := rl.Readline()
		if err != nil {
			break
		}
		fmt.Println(line)
	}
	stdin.Close()
	c.Close()
}
