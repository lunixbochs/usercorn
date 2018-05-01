package cfg

import (
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
)

func Main(args []string) {
	var backtrack, json *bool
	c := cmd.NewUsercornCmd()

	c.SetupFlags = func() error {
		backtrack = c.Flags.Bool("backtrack", false, "recursively backtrack cfg emulator")
		json = c.Flags.Bool("json", false, "use json cfg output")
		return nil
	}
	c.RunUsercorn = func() error {
		c.Usercorn.Gate().Lock()
		go func() {
			err := c.Usercorn.Run()
			if err != nil {
				panic(err)
			}
		}()
		return CfgMain(c.Usercorn, *backtrack, *json)
	}
	os.Exit(c.Run(args, os.Environ()))
}

func init() { cmd.Register("cfg", "explore a program's control flow graph", Main) }
