package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

var helpTxt = `
Commands:
 .alloc <size>
 .read <addr> [size=64]
 .write <addr> <val>
 .regs
`

func parseAddr(u models.Usercorn, line string) uint64 {
	n, _ := strconv.ParseUint(line, 0, 64)
	return n
}

func handleCmd(c *cmd.UsercornCmd, line string) bool {
	u := c.Usercorn
	args := strings.Split(line, " ")

	switch args[0][1:] {
	case "help":
		fmt.Println(helpTxt)
	case "alloc":
		if len(args) != 2 {
			fmt.Println(helpTxt)
		} else {
			addr, err := u.Malloc(parseAddr(u, args[1]), "alloc")
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Printf(" = 0x%x\n", addr)
			}
		}
	case "read":
		if len(args) < 2 {
			fmt.Println(helpTxt)
		} else {
			addr := parseAddr(u, args[1])
			size := uint64(64)
			if len(args) > 2 {
				size = parseAddr(u, args[2])
			}
			mem, err := u.MemRead(addr, size)
			if err != nil {
				fmt.Println(err)
				break
			}
			for _, line := range models.HexDump(addr, mem, int(u.Bits())) {
				fmt.Printf("  %s\n", line)
			}
		}
	case "write":
		if len(args) < 3 {
			fmt.Println(helpTxt)
		} else {
			addr := parseAddr(u, args[1])
			rest := strings.Join(args[2:], " ")
			rest, err := strconv.Unquote("\"" + rest + "\"")
			if err != nil {
				fmt.Println(err)
				break
			}
			err = u.MemWrite(addr, []byte(rest))
			if err != nil {
				fmt.Println(err)
				break
			}
		}
	case "regs":
		status := models.StatusDiff{U: u}
		fmt.Printf("%s", status.Changes(false).String(c.Config.Color))
	default:
		return false
	}
	return true
}

func main() {
	c := cmd.NewUsercornRawCmd()
	c.NoExe = true
	c.NoArgs = true

	c.RunUsercorn = func() error {
		u := c.Usercorn
		addr, err := u.Mmap(u.Entry(), 0x10000, cpu.PROT_ALL, false, "repl", nil)
		if err != nil {
			return err
		}

		status := models.StatusDiff{U: u}
		fmt.Printf("%s", status.Changes(false).String(c.Config.Color))
		end := addr
		input := bufio.NewScanner(os.Stdin)
		for {
			fmt.Printf("%s", status.Changes(true).String(c.Config.Color))
			fmt.Printf("0x%x: ", addr)
			if !input.Scan() {
				break
			}
			text := input.Text()
			if len(text) > 0 && text[0] == '.' {
				if handleCmd(c, text) {
					continue
				}
			}
			sc, err := u.Asm(text, addr)
			if err != nil {
				fmt.Printf("asm err: %s\n", err)
				continue
			}
			if err := u.MemWrite(addr, sc); err != nil {
				fmt.Printf("write err: %s\n", err)
				continue
			}
			end = addr + uint64(len(sc))
			u.SetEntry(addr)
			u.SetExit(end)
			if err := u.Run(); err != nil {
				fmt.Printf("exec err: %s\n", err)
			}
			addr = end
		}
		fmt.Printf("\n%s", status.Changes(false).String(c.Config.Color))
		return nil
	}
	c.Run(os.Args, os.Environ())
}
