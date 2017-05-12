package cpu

import (
	cs "github.com/bnagy/gapstone"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
)

type Capstone struct {
	Arch, Mode int

	cs *cs.Engine
	// FIXME: there's a special case on every capstone just for thumb
	thumb *Capstone
}

func (c *Capstone) Open() (err error) {
	engine, err := cs.New(c.Arch, uint(c.Mode))
	if err == nil {
		c.cs = &engine
	}
	return errors.Wrap(err, "cs.New() failed")
}

func (c *Capstone) Dis(mem []byte, addr uint64) ([]models.Ins, error) {
	if c.cs == nil {
		if err := c.Open(); err != nil {
			return nil, err
		}
	}
	// FIXME: hack, thumb detection should be injected by the ARM arch
	// detect thumb
	if len(mem) == 2 && c.Arch == cs.CS_ARCH_ARM && c.Mode == cs.CS_MODE_ARM {
		if c.thumb == nil {
			c.thumb = &Capstone{Arch: cs.CS_ARCH_ARM, Mode: cs.CS_MODE_THUMB}
		}
		return c.thumb.Dis(mem, addr)
	}
	dis, err := c.cs.Disasm(mem, addr, 0)
	if err != nil {
		return nil, errors.Wrap(err, "capstone disassembly failed")
	}
	ret := make([]models.Ins, len(dis))
	for i, ins := range dis {
		ret[i] = csIns(ins)
	}
	return ret, nil
}

// wrapper to make *gapstone.Instruction conform to the models.Ins interface
type csIns cs.Instruction

func (c csIns) Addr() uint64     { return uint64(c.Address) }
func (c csIns) Bytes() []byte    { return cs.Instruction(c).Bytes }
func (c csIns) Mnemonic() string { return cs.Instruction(c).Mnemonic }
func (c csIns) OpStr() string    { return cs.Instruction(c).OpStr }
