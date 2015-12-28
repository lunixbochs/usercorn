package cmd

import (
	"fmt"
	"io"

	"github.com/lunixbochs/usercorn/go/models"
)

type Context struct {
	io.ReadWriter
	U models.Usercorn
}

func (c *Context) Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(c, format, a...)
}
