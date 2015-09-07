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

type OS struct {
	Name      string
	Init      func(Usercorn)
	Syscall   func(Usercorn)
	Interrupt func(Usercorn, uint32)
}

func (o *OS) String() string {
	return fmt.Sprintf("<OS %s>", o.Name)
}
