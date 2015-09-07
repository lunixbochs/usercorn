package models

import (
	"fmt"
)

type Arch struct {
	Bits    int
	Radare  string
	CS_ARCH int
	CS_MODE uint
	UC_ARCH int
	UC_MODE int
	SP      int
	OS      map[string]*OS
	Regs    map[int]string
}

func (a *Arch) RegisterOS(os *OS) {
	if a.OS == nil {
		a.OS = make(map[string]*OS)
	}
	if _, ok := a.OS[os.Name]; ok {
		panic("Duplicate OS " + os.Name)
	}
	a.OS[os.Name] = os
}

func (a *Arch) RegDump(u Unicorn) (map[string]uint64, error) {
	ret := make(map[string]uint64, len(a.Regs))
	for enum, name := range a.Regs {
		val, err := u.RegRead(enum)
		if err != nil {
			return nil, err
		}
		ret[name] = val
	}
	return ret, nil
}

type OS struct {
	Name      string
	Init      func(Usercorn)
	Syscall   func(Usercorn)
	Interrupt func(Usercorn, uint32)
}

func (o *OS) String() string {
	return fmt.Sprintf("<OS %s>", o.Name)
}
