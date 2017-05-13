package cpu

import (
	cs "github.com/lunixbochs/capstr"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
)

type Capstr struct {
	Arch, Mode int

	cs *cs.Engine
	// FIXME: there's a special case on every capstone just for thumb
	thumb *Capstr
	dc    discache
}

func (c *Capstr) Open() (err error) {
	engine, err := cs.New(c.Arch, c.Mode)
	if err == nil {
		c.cs = engine
		c.dc.cache = make(map[uint64]*discacheEntry)
	}
	return errors.Wrap(err, "cs.New() failed")
}

func (c *Capstr) Dis(mem []byte, addr uint64) ([]models.Ins, error) {
	if c.cs == nil {
		if err := c.Open(); err != nil {
			return nil, err
		}
	}
	// FIXME: hack, thumb detection should be injected by the ARM arch
	// detect thumb
	if len(mem) == 2 && c.Arch == cs.ARCH_ARM && c.Mode == cs.MODE_ARM {
		if c.thumb == nil {
			c.thumb = &Capstr{Arch: cs.ARCH_ARM, Mode: cs.MODE_THUMB}
		}
		return c.thumb.Dis(mem, addr)
	}
	if ent := c.dc.Get(addr, mem); ent != nil {
		return ent.dis, nil
	}
	dis, err := c.cs.Dis(mem, addr, 0)
	if err != nil {
		return nil, errors.Wrap(err, "capstone disassembly failed")
	}
	ret := make([]models.Ins, len(dis))
	for i, v := range dis {
		ret[i] = v
	}
	c.dc.Put(addr, mem, ret)
	return ret, nil
}
