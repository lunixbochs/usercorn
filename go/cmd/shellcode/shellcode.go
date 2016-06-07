package main

import (
	"encoding/hex"
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
)

func main() {
	c := cmd.NewUsercornRawCmd()
	c.NoArgs = true

	var shellcode []byte
	oldMake := c.MakeUsercorn
	c.MakeUsercorn = func(exe string) (models.Usercorn, error) {
		var err error
		shellcode, err = hex.DecodeString(exe)
		if err != nil {
			return nil, err
		}
		return oldMake(exe)
	}
	c.RunUsercorn = func(args, env []string) error {
		u := c.Usercorn
		mem, err := u.Mmap(u.Entry(), uint64(len(shellcode)))
		if err != nil {
			return err
		}
		mem.Desc = "shellcode"
		if err := u.MemWrite(mem.Addr, shellcode); err != nil {
			return err
		}
		u.SetEntry(mem.Addr)
		u.SetExit(mem.Addr + uint64(len(shellcode)))
		return u.Run(args, env)
	}
	c.Run(os.Args, os.Environ())
}
