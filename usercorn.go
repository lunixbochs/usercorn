package main

import (
	"fmt"

	"./arch"
	arch2 "./arch/arch"
	"./loader"
)

type Usercorn struct {
	*Unicorn
	loader    loader.Loader
	Arch      *arch2.Arch
	Bits      int
	Bsz       int
	Entry     uint64
	OS        string
	StackBase uint64
}

const (
	STACK_BASE = 0x7fff000
	STACK_SIZE = 8 * 1024 * 1024
)

func NewUsercorn(exe string) (*Usercorn, error) {
	l, err := loader.LoadFile(exe)
	if err != nil {
		return nil, err
	}
	a, err := arch.GetArch(l.Arch(), l.OS())
	if err != nil {
		return nil, err
	}
	u := &Usercorn{
		loader: l,
		Arch:   a,
		Bits:   l.Bits(),
		Bsz:    l.Bits() / 8,
		OS:     l.OS(),
		Entry:  l.Entry(),
	}
	return u, nil
}

func (u *Usercorn) Run(args ...string) error {
	if err := u.mapMemory(); err != nil {
		return err
	}
	if err := u.setupStack(); err != nil {
		return err
	}
	// envp
	u.Push(0)
	// argv
	if err := u.pushStrings(args...); err != nil {
		return err
	}
	// argc
	u.Push(uint64(len(args)))
	return nil
}

func (u *Usercorn) mapMemory() error {
	segments, err := u.loader.Segments()
	if err != nil {
		return err
	}
	for _, seg := range segments {
		fmt.Printf("0x%x\n", seg.Addr)
	}
	return nil
}

func (u *Usercorn) setupStack() error {
	stack, err := u.Mmap(STACK_BASE, STACK_SIZE)
	if err != nil {
		return err
	}
	u.StackBase = stack
	if err := u.RegWrite(u.Arch.SP, stack+STACK_SIZE-uint64(u.Bsz)); err != nil {
		return err
	}
	return nil
}

func (u *Usercorn) pushStrings(args ...string) error {
	argvSize := 0
	for _, v := range args {
		argvSize += len(v) + 1
	}
	argvAddr, err := u.Mmap(0, uint64(argvSize))
	if err != nil {
		return err
	}
	buf := make([]byte, argvSize)
	addrs := make([]uint64, 0, len(args)+1)
	var pos uint64
	for i := len(args) - 1; i >= 0; i-- {
		copy(buf[pos:], []byte(args[i]))
		addrs = append(addrs, argvAddr+pos)
		pos += uint64(len(args[i]) + 1)
	}
	u.Push(0)
	for _, v := range addrs {
		u.Push(v)
	}
	return nil
}
