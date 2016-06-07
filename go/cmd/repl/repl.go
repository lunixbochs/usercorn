package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
)

func main() {
	c := cmd.NewUsercornRawCmd()
	c.NoExe = true
	c.NoArgs = true

	c.RunUsercorn = func(args, env []string) error {
		u := c.Usercorn
		mem, err := u.Mmap(u.Entry(), 0x10000)
		if err != nil {
			return err
		}
		mem.Desc = "repl"

		status := models.StatusDiff{U: u}
		u.Printf("%s", status.Changes(false).String("", c.Config.Color))
		addr := mem.Addr
		end := addr
		input := bufio.NewScanner(os.Stdin)
		fmt.Printf("0x%x: ", addr)
		for input.Scan() {
			sc, err := u.Assemble(input.Text(), addr)
			if err != nil {
				u.Printf("asm err: %s\n", err)
				goto end
			}
			if err := u.MemWrite(addr, sc); err != nil {
				u.Printf("write err: %s\n", err)
				goto end
			}
			end = addr + uint64(len(sc))
			u.SetEntry(addr)
			u.SetExit(end)
			if err := u.Run(os.Args, os.Environ()); err != nil {
				u.Printf("exec err: %s\n", err)
			}
			addr = end
		end:
			u.Printf("%s", status.Changes(true).String("", c.Config.Color))
			fmt.Printf("0x%x: ", addr)
		}
		u.Printf("\n%s", status.Changes(false).String("", c.Config.Color))
		return nil
	}
	c.Run(os.Args, os.Environ())
}
