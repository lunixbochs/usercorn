package main

import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func main() {
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
	c.RunUsercorn = func(args, env []string) error {
		u := c.Usercorn
		mem, err := u.Mmap(u.Entry(), 0x2000)
		if err != nil {
			return err
		}
		mem.Desc = "shellcode"
		if err := u.MemWrite(mem.Addr, shellcode); err != nil {
			return err
		}
		resultBuf, err := u.Mmap(0, 0x4096)
		if err != nil {
			return err
		}
		u.HookAdd(uc.HOOK_CODE, func(_ uc.Unicorn, addr uint64, size uint32) {
			u.Push(0)
			u.Push(resultBuf.Addr)
			u.Push(resultBuf.Addr) // return pointer
		}, 0x100000, 0x100000)
		u.HookAdd(uc.HOOK_CODE, func(_ uc.Unicorn, addr uint64, size uint32) {
			u.Stop()
		}, 0x102000, 0x102000)

		// u.RegWrite(uc.X86_REG_RDI, resultBuf.Addr)

		u.SetEntry(mem.Addr) // + 0x40)
		u.SetExit(mem.Addr + uint64(len(shellcode)))
		err = u.Run(args, env)

		rax, _ := u.RegRead(uc.X86_REG_RAX)
		out, _ := u.MemRead(resultBuf.Addr, rax)
		if err := ioutil.WriteFile("out.bin", out, 0644); err != nil {
			fmt.Println("error writing output file", err)
		}

		fmt.Println("done!", err, rax)
		return err
	}
	c.Run(os.Args, os.Environ())
}
