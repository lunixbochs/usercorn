package main

import (
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
)

func main() {
	var backtrack, json *bool
	c := cmd.NewUsercornCmd()

	c.SetupFlags = func() error {
		backtrack = c.Flags.Bool("backtrack", false, "recursively backtrack cfg emulator")
		json = c.Flags.Bool("json", false, "use json cfg output")
		return nil
	}
	c.RunUsercorn = func(args, env []string) error {
		c.Usercorn.Gate().Lock()
		go func() {
			err := c.Usercorn.Run(args, env)
			if err != nil {
				panic(err)
			}
		}()
		return CfgMain(c.Usercorn, *backtrack, *json)
	}
	c.Run(os.Args, os.Environ())
}
