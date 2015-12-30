package cmd

import (
	"github.com/lunixbochs/usercorn/go/models"
)

var MapsCmd = cmd(&Command{
	Name: "maps",
	Desc: "Display memory mappings.",
	// TODO: once we have command overloading, merge this with mem command
	Run: func(c *Context) error {
		for _, m := range c.U.Mappings() {
			c.Printf("  %v\n", m.String())
		}
		return nil
	},
})

var MemCmd = cmd(&Command{
	Name: "mem",
	Desc: "Read/write memory.",
	// TODO: need overloading so we can keep arg safety
	// at that point optional args might as well be an overloaded form
	Run: func(c *Context, addr, size uint64) error {
		mem, err := c.U.MemRead(addr, size)
		if err != nil {
			return err
		}
		for _, line := range models.HexDump(addr, mem, int(c.U.Bits())) {
			c.Printf("  %s\n", line)
		}
		return nil
	},
})
