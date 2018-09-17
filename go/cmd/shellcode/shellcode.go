package shellcode

import (
	"encoding/hex"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

func Main(args []string) {
	c := cmd.NewUsercornRawCmd()
	c.NoArgs = true

	var shellcode []byte
	oldMake := c.MakeUsercorn
	c.MakeUsercorn = func(exe string) (models.Usercorn, error) {
		var err error
		if exe == "-" {
			shellcode, err = ioutil.ReadAll(os.Stdin)
		} else {
			shellcode, err = hex.DecodeString(exe)
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to read shellcode")
		}
		return oldMake(exe)
	}
	c.RunUsercorn = func() error {
		u := c.Usercorn
		size := uint64(len(shellcode))
		addr, err := u.Mmap(u.Entry(), size, cpu.PROT_ALL, false, "shellcode", nil)
		if err != nil {
			return err
		}
		if err := u.MemWrite(addr, shellcode); err != nil {
			return err
		}
		u.SetEntry(addr)
		u.SetExit(addr + size)
		return u.Run()
	}
	c.Run(args[1:], os.Environ())
}

func init() { cmd.Register("shellcode", "execute a blob of machine code directly", Main) }
