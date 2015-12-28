package cmd

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
			// assume read for now
			// in the future, reg=val can *write*
			// uhh maybe we should care if cpu is running?
			// could put that as a command attribute (along with whether we want optional args)
			for _, v := range args {
				for enum, name := range c.U.Arch().Regs {
					if v == name {
						val, _ := c.U.RegRead(enum)
						c.Printf("%s 0x%x\n", name, val)
					}
				}
			}
		}
		return nil
	},
})
