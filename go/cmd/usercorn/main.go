package main

import (
	"github.com/lunixbochs/usercorn/go/cmd"
)

import (
	"os"
)

func main() {
	cmd.NewUsercornCmd().Run(os.Args, os.Environ())
}
