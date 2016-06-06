package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

func main() {
	c := cmd.NewUsercornCmd()

	var shellcode []byte
	var entry *uint64
	var arch, osStr, endian *string
	c.MakeUsercorn = func(exe string) (models.Usercorn, error) {
		var byteOrder binary.ByteOrder
		switch *endian {
		case "little":
			byteOrder = binary.LittleEndian
		case "big":
			byteOrder = binary.BigEndian
		default:
			return nil, fmt.Errorf("%s is not a valid byte order ('little' or 'big')", endian)
		}
		var err error
		shellcode, err = hex.DecodeString(exe)
		if err != nil {
			return nil, err
		}
		l := loader.NewNullLoader(*arch, *osStr, byteOrder, *entry)
		u, err := usercorn.NewUsercornRaw(l, c.Config)
		if err != nil {
			return nil, err
		}
		return u, nil
	}
	c.RunUsercorn = func(args, env []string) error {
		u := c.Usercorn
		mem, err := u.Mmap(*entry, uint64(len(shellcode)))
		if err != nil {
			return err
		}
		mem.Desc = "shellcode"
		if err := u.MemWrite(mem.Addr, shellcode); err != nil {
			return err
		}
		*entry = mem.Addr
		u.SetEntry(mem.Addr)
		u.SetExit(mem.Addr + uint64(len(shellcode)))
		return u.Run(args, env)
	}
	c.SetupFlags = func() error {
		entry = c.Flags.Uint64("entry", 0, "shellcode entry point")
		arch = c.Flags.String("arch", "x86", "target architecture")
		osStr = c.Flags.String("os", "linux", "target OS")
		endian = c.Flags.String("endian", "little", "'big' or 'little' endian")
		return nil
	}
	c.Run(os.Args, os.Environ())
}
