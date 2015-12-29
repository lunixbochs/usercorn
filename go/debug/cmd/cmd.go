package cmd

import (
	"fmt"
	"github.com/lunixbochs/argjoy"
	"github.com/lunixbochs/go-shellwords"
	"io"
	"reflect"

	"github.com/lunixbochs/usercorn/go/models"
)

type Command struct {
	Name string
	Desc string
	Run  interface{}
}

var Commands = make(map[string]*Command)

func cmd(c *Command) *Command {
	fn := reflect.ValueOf(c.Run)
	if !fn.IsValid() || fn.Kind() != reflect.Func {
		panic(fmt.Sprintf("Command.Run must be a func: got (%T) %#v\n", c.Run, c.Run))
	}
	Commands[c.Name] = c
	return c
}

type Context struct {
	io.ReadWriter
	U models.Usercorn
}

func (c *Context) Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(c, format, a...)
}

var aj = argjoy.NewArgjoy()

func Run(c *Context, line string) error {
	args, err := shellwords.Parse(line)
	if err != nil {
		c.Printf("parse error: %v\n", err)
		return nil
	}
	if len(args) == 0 {
		return nil
	}
	name, args := args[0], args[1:]
	if cmd, ok := Commands[name]; ok {
		out, err := aj.Call(cmd.Run, c, args)
		if err != nil {
			c.Printf("error: %v\n", err)
		}
		if len(out) > 0 {
			if err, ok := out[0].(error); ok {
				c.Printf("error: %v\n", err)
			}
		}
	} else {
		c.Printf("command not found.\n")
	}
	return nil
}
