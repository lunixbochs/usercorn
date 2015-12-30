package cmd

import (
	"regexp"
	"strconv"
	"strings"
)

var strEqNumRe = regexp.MustCompile(`^([a-zA-Z]+)=((-|0|0x|0b)?\d+)$`)

var RegCmd = cmd(&Command{
	Name: "reg",
	Desc: "Read/write regs.",
	Run: func(c *Context, args ...string) error {
		if len(args) == 0 {
			regs, err := c.U.RegDump()
			if err != nil {
				return err
			}
			for _, reg := range regs {
				c.Printf("%s 0x%x\n", reg.Name, reg.Val)
			}
		} else {
			// maybe we should care if cpu is running?
			// could put that as a command attribute (along with whether we want optional args)
			for _, v := range args {
				var value uint64
				reg := v
				// check for assignment
				match := strEqNumRe.FindStringSubmatch(v)
				if len(match) > 0 {
					reg = match[1]
					var err error
					if match[2][0] == '-' {
						var n int64
						n, err = strconv.ParseInt(match[2], 0, int(c.U.Bits()))
						value = uint64(n)
					} else {
						value, err = strconv.ParseUint(match[2], 0, int(c.U.Bits()))
					}
					if err != nil {
						c.Printf("error parsing %s value: %v\n", reg, err)
						continue
					}
				}
				// look for register and print or assign
				valid := false
				for enum, name := range c.U.Arch().Regs {
					if reg == name {
						valid = true
						// match > 0 = valid assignment
						if len(match) > 0 {
							if err := c.U.RegWrite(enum, value); err != nil {
								c.Printf("%s: %v\n", v, err)
							}
						} else {
							val, _ := c.U.RegRead(enum)
							c.Printf("%s 0x%x\n", name, val)
						}
						break
					}
				}
				if !valid {
					if strings.Contains(reg, "=") {
						c.Printf("invalid assignment: %s\n", reg)
					} else {
						c.Printf("reg %s not found\n", reg)
					}
				}
			}
		}
		return nil
	},
})
