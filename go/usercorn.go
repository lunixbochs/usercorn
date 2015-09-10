package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"os"
	"path/filepath"

	"./arch"
	"./loader"
	"./models"
	"./syscalls"
)

type Usercorn struct {
	*Unicorn
	loader loader.Loader

	interpBase uint64
	entry      uint64
	binEntry   uint64

	StackBase   uint64
	DataSegment models.Segment
	Verbose     bool
	TraceSys    bool
	TraceMem    bool
	TraceExec   bool
	TraceReg    bool
	LoadPrefix  string
	status      models.StatusDiff

	// deadlock detection
	lastBlock uint64
	lastCode  uint64
	deadlock  int
}

func NewUsercorn(exe string, prefix string) (*Usercorn, error) {
	l, err := loader.LoadFile(exe)
	if err != nil {
		return nil, err
	}
	a, os, err := arch.GetArch(l.Arch(), l.OS())
	if err != nil {
		return nil, err
	}
	unicorn, err := NewUnicorn(a, os, l.ByteOrder())
	if err != nil {
		return nil, err
	}
	ds, de := l.DataSegment()
	u := &Usercorn{
		Unicorn:     unicorn,
		loader:      l,
		LoadPrefix:  prefix,
		DataSegment: models.Segment{ds, de},
	}
	u.status = models.StatusDiff{U: u, Color: true}
	u.interpBase, u.entry, u.binEntry, err = u.mapBinary(u.loader)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *Usercorn) Run(args []string, env []string) error {
	if err := u.addHooks(); err != nil {
		return err
	}
	if err := u.setupStack(); err != nil {
		return err
	}
	if u.OS.Init != nil {
		if err := u.OS.Init(u, args, env); err != nil {
			return err
		}
	}
	if u.Verbose {
		fmt.Fprintf(os.Stderr, "[entry point @ 0x%x]\n", u.entry)
		dis, err := u.Disas(u.entry, 64)
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
	}
	if u.Verbose || u.TraceReg {
		u.status.Changes().Print(true, false)
	}
	if u.Verbose {
		fmt.Fprintln(os.Stderr, "=====================================")
		fmt.Fprintln(os.Stderr, "==== Program output begins here. ====")
		fmt.Fprintln(os.Stderr, "=====================================")
	}
	return u.Unicorn.Start(u.entry, 0xffffffffffffffff)
}

func (u *Usercorn) Loader() loader.Loader {
	return u.loader
}

func (u *Usercorn) InterpBase() uint64 {
	// points to interpreter base or 0
	return u.interpBase
}

func (u *Usercorn) Entry() uint64 {
	// points to effective program entry: either an interpreter or the binary
	return u.entry
}

func (u *Usercorn) BinEntry() uint64 {
	// points to binary entry, even if an interpreter is used
	return u.entry
}

func (u *Usercorn) PosixInit(args, env []string, auxv []byte) error {
	// end marker
	if err := u.Push(0); err != nil {
		return err
	}
	// auxv
	if err := u.PushBytes(auxv); err != nil {
		return err
	}
	// envp
	envp, err := u.pushStrings(env...)
	if err != nil {
		return err
	}
	if err := u.pushAddrs(envp); err != nil {
		return err
	}
	// argv
	argv, err := u.pushStrings(args...)
	if err != nil {
		return err
	}
	if err := u.pushAddrs(argv); err != nil {
		return err
	}
	// argc
	return u.Push(uint64(len(args)))
}

func (u *Usercorn) PrefixPath(path string, force bool) string {
	if filepath.IsAbs(path) && u.LoadPrefix != "" {
		_, err := os.Stat(path)
		exists := !os.IsNotExist(err)
		if force || exists {
			return filepath.Join(u.LoadPrefix, path)
		}
	}
	return path
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
	if u.TraceExec || u.TraceReg {
		u.HookAdd(uc.HOOK_BLOCK, func(_ uc.Unicorn, addr uint64, size uint32) {
			sym, _ := u.Symbolicate(addr)
			if sym != "" {
				sym = " (" + sym + ")"
			}
			blockLine := fmt.Sprintf("| block%s @0x%x", sym, addr)
			if !u.TraceExec && u.TraceReg && u.deadlock == 0 {
				changes := u.status.Changes()
				if changes.Count() > 0 {
					fmt.Fprintln(os.Stderr, blockLine)
					changes.Print(true, true)
				}
			} else {
				fmt.Fprintln(os.Stderr, blockLine)
			}
			u.lastBlock = addr
		})
	}
	if u.TraceExec {
		u.HookAdd(uc.HOOK_CODE, func(_ uc.Unicorn, addr uint64, size uint32) {
			var changes *models.Changes
			if addr == u.lastCode || u.TraceReg && u.TraceExec {
				changes = u.status.Changes()
			}
			if u.TraceExec {
				if u.TraceReg {
					changes.Print(true, true)
				}
				dis, _ := u.Disas(addr, uint64(size))
				fmt.Fprintln(os.Stderr, dis)
			}
			if addr == u.lastCode {
				u.deadlock++
				if changes.Count() > 0 {
					if u.TraceReg {
						changes.Print(true, true)
					}
					u.deadlock = 0
				}
				if u.deadlock > 2 {
					sym, _ := u.Symbolicate(addr)
					if sym != "" {
						sym = " (" + sym + ")"
					}
					fmt.Fprintf(os.Stderr, "FATAL: deadlock detected at 0x%x%s\n", addr, sym)
					changes.Print(true, false)
					u.Stop()
				}
			} else {
				u.deadlock = 0
			}
			u.lastCode = addr
		})
	}
	if u.TraceMem {
		u.HookAdd(uc.HOOK_MEM_READ_WRITE, func(_ uc.Unicorn, access int, addr uint64, size int, value int64) {
			if access == uc.MEM_WRITE {
				fmt.Fprintf(os.Stderr, "MEM_WRITE")
			} else {
				fmt.Fprintf(os.Stderr, "MEM_READ")
			}
			fmt.Fprintf(os.Stderr, " 0x%x %d 0x%x\n", addr, size, value)
		})
	}
	u.HookAdd(uc.HOOK_MEM_INVALID, func(_ uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		if access == uc.MEM_WRITE {
			fmt.Fprintf(os.Stderr, "invalid write")
		} else {
			fmt.Fprintf(os.Stderr, "invalid read")
		}
		fmt.Fprintf(os.Stderr, ": @0x%x, 0x%x = 0x%x\n", addr, size, value)
		u.status.Changes().Print(true, false)
		return false
	})
	u.HookAdd(uc.HOOK_INTR, func(_ uc.Unicorn, intno uint32) {
		u.OS.Interrupt(u, intno)
	})
	return nil
}

func (u *Usercorn) mapBinary(l loader.Loader) (interpBase, realEntry, entry uint64, err error) {
	var dynamic bool
	switch l.Type() {
	case loader.EXEC:
		dynamic = false
	case loader.DYN:
		dynamic = true
	default:
		err = errors.New("Unsupported file load type.")
		return
	}
	segments, err := l.Segments()
	if err != nil {
		return
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
	// map merged segments
	var loadBias uint64
	for _, seg := range merged {
		size := seg.End - seg.Start
		if dynamic && seg.Start == 0 && loadBias == 0 {
			loadBias, err = u.Mmap(0x1000000, size)
		} else {
			err = u.MemMap(loadBias+seg.Start, seg.End-seg.Start)
		}
		if err != nil {
			return
		}
	}
	// write segment memory
	for _, seg := range segments {
		if err := u.MemWrite(loadBias+seg.Addr, seg.Data); err != nil {
			return 0, 0, 0, err
		}
	}
	entry = loadBias + l.Entry()
	// load interpreter if present
	interp := l.Interp()
	if interp != "" {
		bin, err := loader.LoadFile(u.PrefixPath(interp, true))
		if err != nil {
			return 0, 0, 0, err
		}
		_, interpEntry, interpBias, err := u.mapBinary(bin)
		return interpBias, interpEntry, entry, err
	} else {
		return 0, entry, entry, nil
	}
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

func (u *Usercorn) pushStrings(args ...string) ([]uint64, error) {
	// TODO: does anything case if these are actually on the stack?
	argvSize := 0
	for _, v := range args {
		argvSize += len(v) + 1
	}
	argvAddr, err := u.Mmap(0, uint64(argvSize))
	if err != nil {
		return nil, err
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
	return addrs, nil
}

func (u *Usercorn) pushAddrs(addrs []uint64) error {
	if err := u.Push(0); err != nil {
		return err
	}
	for _, v := range addrs {
		if err := u.Push(v); err != nil {
			return err
		}
	}
	return nil
}

func (u *Usercorn) Syscall(num int, name string, getArgs func(n int) ([]uint64, error)) (uint64, error) {
	if name == "" {
		panic(fmt.Sprintf("Syscall missing: %d", num))
	}
	return syscalls.Call(u, num, name, getArgs, u.TraceSys)
}
