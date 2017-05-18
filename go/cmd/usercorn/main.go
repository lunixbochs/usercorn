package main

import (
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
)

func main() {
	os.Exit(cmd.NewUsercornCmd().Run(os.Args, os.Environ()))
}
