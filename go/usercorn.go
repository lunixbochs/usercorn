package main

import (
	"encoding/hex"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"os"

	"./arch"
	"./loader"
	"./models"
	"./syscalls"
)

type Usercorn struct {
	*Unicorn
	loader      loader.Loader
	Entry       uint64
	StackBase   uint64
	DataSegment *models.Segment
	Verbose     bool
	TraceSys    bool
	TraceMem    bool
	TraceExec   bool
}

func NewUsercorn(exe string) (*Usercorn, error) {
	l, err := loader.LoadFile(exe)
	if err != nil {
		return nil, err
	}
	a, os, err := arch.GetArch(l.Arch(), l.OS())
	if err != nil {
		return nil, err
	}
	unicorn, err := NewUnicorn(a, os)
	if err != nil {
		return nil, err
	}
	ds, de := l.DataSegment()
	u := &Usercorn{
		Unicorn:     unicorn,
		loader:      l,
		Entry:       l.Entry(),
		DataSegment: &models.Segment{ds, de},
	}
	return u, nil
}

func (u *Usercorn) Run(args ...string) error {
	if err := u.addHooks(); err != nil {
		return err
	}
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

	if u.Verbose {
		fmt.Fprintf(os.Stderr, "[entry point @ 0x%x]\n", u.Entry)
		dis, err := u.Disas(u.Entry, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		} else {
			fmt.Fprintln(os.Stderr, dis)
		}
		sp, err := u.RegRead(u.arch.SP)
		if err != nil {
			return err
		}
		buf := make([]byte, u.StackBase+STACK_SIZE-sp)
		if err := u.MemReadInto(buf, sp); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[stack @ 0x%x] %s\n", sp, hex.EncodeToString(buf[:]))

		fmt.Fprintln(os.Stderr, "=====================================")
		fmt.Fprintln(os.Stderr, "==== Program output begins here. ====")
		fmt.Fprintln(os.Stderr, "=====================================")
	}
	return u.Uc.Start(u.Entry, 0xffffffffffffffff)
}

func (u *Usercorn) Symbolicate(addr uint64) (string, error) {
	return u.loader.Symbolicate(addr)
}

func (u *Usercorn) Brk(addr uint64) (uint64, error) {
	// TODO: this is linux specific
	s := u.DataSegment
	if addr > 0 {
		u.MemMap(s.End, addr)
		s.End = addr
	}
	return s.End, nil
}

func (u *Usercorn) addHooks() error {
	if u.TraceExec {
		u.HookAdd(uc.UC_HOOK_BLOCK, func(_ *uc.Uc, addr uint64, size uint32) {
			sym, _ := u.Symbolicate(addr)
			if sym != "" {
				sym = " (" + sym + ")"
			}
			fmt.Fprintf(os.Stderr, "-- block%s @0x%x (size 0x%x) --\n", sym, addr, size)
			dis, _ := u.Disas(addr, uint64(size))
			if dis != "" {
				fmt.Fprintln(os.Stderr, dis)
			}
		})
		u.HookAdd(uc.UC_HOOK_CODE, func(_ *uc.Uc, addr uint64, size uint32) {
			dis, _ := u.Disas(addr, uint64(size))
			fmt.Fprintln(os.Stderr, dis)
		})
	}
	if u.TraceMem {
		u.HookAdd(uc.UC_HOOK_MEM_READ_WRITE, func(_ *uc.Uc, access int, addr uint64, size int, value int64) {
			if access == uc.UC_MEM_WRITE {
				fmt.Fprintf(os.Stderr, "MEM_WRITE")
			} else {
				fmt.Fprintf(os.Stderr, "MEM_READ")
			}
			fmt.Fprintf(os.Stderr, " 0x%x %d 0x%x\n", addr, size, value)
		})
	}
	u.HookAdd(uc.UC_HOOK_MEM_INVALID, func(_ *uc.Uc, access int, addr uint64, size int, value int64) bool {
		if access == uc.UC_MEM_WRITE {
			fmt.Fprintf(os.Stderr, "invalid write")
		} else {
			fmt.Fprintf(os.Stderr, "invalid read")
		}
		ip, _ := u.RegRead(uc.UC_X86_REG_EIP)
		fmt.Fprintf(os.Stderr, ": @0x%x, 0x%x = 0x%x (eip: 0x%x)\n", addr, size, value, ip)
		dis, _ := u.Disas(ip, 8)
		fmt.Fprintln(os.Stderr, dis)
		return false
	})
	u.HookAdd(uc.UC_HOOK_INTR, func(_ *uc.Uc, intno uint32) {
		u.OS.Interrupt(u, intno)
	})
	u.HookAdd(uc.UC_HOOK_INSN, func(_ *uc.Uc) {
		u.OS.Syscall(u)
	}, uc.UC_X86_INS_SYSCALL)
	return nil
}

func (u *Usercorn) mapMemory() error {
	segments, err := u.loader.Segments()
	if err != nil {
		return err
	}
	// merge overlapping segments
	merged := make([]*models.Segment, 0, len(segments))
outer:
	for _, seg := range segments {
		addr, size := align(seg.Addr, uint64(len(seg.Data)), true)
		s := &models.Segment{addr, addr + size}
		for _, s2 := range merged {
			if s2.Overlaps(s) {
				s2.Merge(s)
				continue outer
			}
		}
		merged = append(merged, s)
	}
	for _, seg := range merged {
		if err := u.MemMap(seg.Start, seg.End-seg.Start); err != nil {
			return err
		}
	}
	for _, seg := range segments {
		if err := u.MemWrite(seg.Addr, seg.Data); err != nil {
			return err
		}
	}
	return nil
}

func (u *Usercorn) setupStack() error {
	stack, err := u.Mmap(STACK_BASE, STACK_SIZE)
	if err != nil {
		return err
	}
	u.StackBase = stack
	if err := u.RegWrite(u.arch.SP, stack+STACK_SIZE); err != nil {
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
	u.MemWrite(argvAddr, buf)
	u.Push(0)
	for _, v := range addrs {
		u.Push(v)
	}
	return nil
}

func (u *Usercorn) Syscall(table map[int]string, n int, getArgs func(n int) ([]uint64, error)) (uint64, error) {
	name, ok := table[n]
	if !ok {
		panic(fmt.Sprintf("Syscall missing: %d", n))
		return 0, fmt.Errorf("OS has no syscall: %d", n)
	}
	return syscalls.Call(u, name, getArgs, u.TraceSys)
}
