package usercorn

import (
	"bufio"
	"fmt"
	"github.com/lunixbochs/ghostrace/ghost/memio"
	"github.com/lunixbochs/readline"
	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/lunixbochs/usercorn/go/arch"
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
	"github.com/lunixbochs/usercorn/go/models/debug"
	"github.com/lunixbochs/usercorn/go/models/trace"
	"github.com/lunixbochs/usercorn/go/ui"
)

// #cgo LDFLAGS: -Wl,-rpath -Wl,$ORIGIN/deps/lib:$ORIGIN/lib
import "C"

type tramp struct {
	desc string
	fun  func() error
}

type Usercorn struct {
	*Task

	sync.Mutex
	config       *models.Config
	exe          string
	loader       models.Loader
	interpLoader models.Loader
	kernels      []co.Kernel
	memio        memio.MemIO

	base       uint64
	interpBase uint64
	entry      uint64
	exit       uint64
	binEntry   uint64

	StackBase uint64
	StackSize uint64
	brk       uint64

	final      sync.Once
	exitStatus error

	running     bool
	trampolines []tramp
	trampolined bool
	stackinit   bool

	restart func(models.Usercorn, error) error

	gate models.Gate

	breaks       []*models.Breakpoint
	futureBreaks []*models.Breakpoint

	hooks    []cpu.Hook
	sysHooks []*models.SysHook

	debug    *debug.Debug
	trace    *trace.Trace
	replay   *trace.Replay
	rewind   []models.Op
	ui       *ui.StreamUI
	inscount uint64
}

func NewUsercornRaw(l models.Loader, config *models.Config) (*Usercorn, error) {
	config = config.Init()

	a, OS, err := arch.GetArch(l.Arch(), l.OS())
	if err != nil {
		return nil, err
	}
	cpu, err := a.Cpu.New()
	if err != nil {
		return nil, err
	}
	task := NewTask(cpu, a, OS, l.ByteOrder())
	u := &Usercorn{
		Task:   task,
		config: config,
		loader: l,
		exit:   0xffffffffffffffff,
		debug:  debug.NewDebug(l.Arch(), config),
	}
	if u.config.Rewind || u.config.UI {
		u.replay = trace.NewReplay(u.arch, u.os, l.ByteOrder(), u.debug)
		config.Trace.OpCallback = append(config.Trace.OpCallback, u.replay.Feed)
		if config.UI {
			u.ui = ui.NewStreamUI(u.config, u.replay)
			u.replay.Listen(u.ui.Feed)
		}
		if u.config.Rewind {
			u.rewind = make([]models.Op, 0, 10000)
			config.Trace.OpCallback = append(config.Trace.OpCallback,
				func(frame models.Op) {
					u.rewind = append(u.rewind, frame)
				})
		}
	}
	u.trace, err = trace.NewTrace(u, &config.Trace)
	if err != nil {
		return nil, errors.Wrap(err, "NewTrace() failed")
	}
	if config.Output == os.Stderr && readline.IsTerminal(int(os.Stderr.Fd())) {
		config.Color = true
	}
	u.memio = memio.NewMemIO(
		// ReadAt() callback
		func(p []byte, addr uint64) (int, error) {
			if err := u.Task.MemReadInto(p, addr); err != nil {
				return 0, err
			}
			if u.trace != nil && u.config.Trace.Mem {
				u.trace.OnMemReadSize(addr, uint32(len(p)))
			}
			return len(p), nil
		},
		// WriteAt() callback
		func(p []byte, addr uint64) (int, error) {
			if err := u.Task.MemWrite(addr, p); err != nil {
				return 0, err
			}
			if u.trace != nil && u.config.Trace.Mem {
				u.trace.OnMemWrite(addr, p)
			}
			return len(p), nil
		},
	)
	// load kernels
	// the array cast is a trick to work around circular imports
	if OS.Kernels != nil {
		kernelI := OS.Kernels(u)
		kernels := make([]co.Kernel, len(kernelI))
		for i, k := range kernelI {
			kernels[i] = k.(co.Kernel)
		}
		u.kernels = kernels
	}
	return u, nil
}

func NewUsercorn(exe string, config *models.Config) (models.Usercorn, error) {
	config = config.Init()

	f, err := os.Open(exe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l, err := loader.Load(f)
	if err == loader.UnknownMagic {
		f.Seek(0, 0)
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#!") && len(line) > 2 {
				args := strings.Split(line[2:], " ")
				prefix := append(args[1:], exe)
				config.PrefixArgs = append(prefix, config.PrefixArgs...)
				shell := config.PrefixPath(args[0], false)
				return NewUsercorn(shell, config)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	u, err := NewUsercornRaw(l, config)
	if err != nil {
		return nil, err
	}
	exe, _ = filepath.Abs(exe)
	u.exe = exe
	u.loader = l

	// map binary (and interp) into memory
	u.interpBase, u.entry, u.base, u.binEntry, err = u.mapBinary(f, false)
	if err != nil {
		return nil, err
	}
	// find data segment for brk
	u.brk = 0
	segments, err := l.Segments()
	if err != nil {
		return nil, err
	}
	for _, seg := range segments {
		if seg.Prot&cpu.PROT_WRITE != 0 {
			addr := u.base + seg.Addr + seg.Size
			if addr > u.brk {
				u.brk = addr
			}
		}
	}
	// TODO: have a "host page size", maybe arch.Align()
	// TODO: allow setting brk addr for raw Usercorn?
	if u.brk > 0 {
		mask := uint64(4096)
		u.brk = (u.brk + mask) & ^(mask - 1)
	}
	// make sure PC is set to entry point for debuggers
	u.RegWrite(u.Arch().PC, u.Entry())
	return u, nil
}

func (u *Usercorn) Rewind(by, addr uint64) error {
	if !u.config.Rewind {
		return errors.New("rewind not enabled in config")
	}
	var target uint64
	if by > 0 {
		if u.replay.Inscount < by {
			// TODO: just rewind to start when this happens?
			return errors.New("rewinding too far")
		}
		target = u.replay.Inscount - by
	}
	replay := trace.NewReplay(u.arch, u.os, u.ByteOrder(), u.debug)
	good := false
	var pos int
	var op models.Op
	// TODO: attach a StreamUI to remainder, but reverse the lines?
	// do this if you want to see the trace getting replayed (forwards)
	/*
		ui := ui.NewStreamUI(u.config, replay)
		replay.Listen(ui.Feed)
	*/
outer:
	for pos, op = range u.rewind {
		if target > 0 && replay.Inscount == target {
			good = true
			break
		} else if target == 0 && replay.PC == addr {
			if good {
				// we need to confirm the addr isn't just the implicit pc after a call
				// by checking for an OpJmp after
				switch v := op.(type) {
				case *trace.OpStep:
					break outer
				case *trace.OpJmp:
					if v.Addr == addr {
						break outer
					}
				}
			}
			good = true
		}
		replay.Feed(op)
	}
	if !good {
		return errors.Errorf("missed rewind target (%d), hit %d", target, replay.Inscount)
	}
	//* sync simulated cpu *//
	// 1. copy reg state FIXME: USE RegReadFast
	// we use u.replay.Regs for the enums, because replay.Regs might not have all regs set
	for enum, oldval := range u.replay.Regs {
		newval, _ := replay.Regs[enum]
		if oldval != newval {
			name := u.Arch().RegNames()[enum]
			if u.config.UI {
				u.Printf("  %s (%#x) -> (%#x)\n", name, oldval, newval)
			}
			u.RegWrite(enum, newval)
		}
	}
	if u.config.UI {
		u.Printf("  pc %#x -> %#x\n", u.replay.PC, replay.PC)
	}
	pc := replay.PC
	u.RegWrite(u.arch.PC, pc)
	// TODO: special regs (SpRegs)

	// 2. map all target mappings
	for _, mm := range replay.Mem.Maps() {
		if err := u.MemMap(mm.Addr, mm.Size, mm.Prot); err != nil {
			return err
		}
		// 3. copy target memory
		if err := u.MemWrite(mm.Addr, mm.Data); err != nil {
			return err
		}
	}
	// 4. truncate our rewind state
	// TODO: instead of truncating, undo tree to allow ff/diff?
	u.rewind = u.rewind[:pos+1]

	// 5. tell trace we rewound so it updates register diffs
	u.trace.Rewound()

	// 6. dis our new current pc
	mem, _ := u.DirectRead(pc, 16)
	dis, err := u.Arch().Dis.Dis(mem, pc)
	if err == nil && len(dis) > 0 {
		padto := len(fmt.Sprintf("%#x", dis[0].Addr())) + 1
		pad := strings.Repeat("<", padto)
		if u.config.UI {
			u.Printf("%s %s %s\n", pad, dis[0].Mnemonic(), dis[0].OpStr())
		}
	}

	// 7. gross: update old replay with new data (so we don't need to mess with callbacks/defer)
	u.replay.Mem = replay.Mem
	u.replay.Regs = replay.Regs
	u.replay.SpRegs = replay.SpRegs
	u.replay.PC = replay.PC
	u.replay.SP = replay.SP
	u.replay.Inscount = replay.Inscount
	return nil
}

// Intercept memory read/write into MemIO to make tracing always work.
// This means Trace needs to use Task().Read() instead
func (u *Usercorn) MemWrite(addr uint64, p []byte) error {
	_, err := u.memio.WriteAt(p, addr)
	return err
}
func (u *Usercorn) MemReadInto(p []byte, addr uint64) error {
	_, err := u.memio.ReadAt(p, addr)
	return err
}
func (u *Usercorn) MemRead(addr, size uint64) ([]byte, error) {
	p := make([]byte, size)
	err := u.MemReadInto(p, addr)
	return p, err
}

// read without tracing, used by trace and repl
func (u *Usercorn) DirectRead(addr, size uint64) ([]byte, error) {
	return u.Task.MemRead(addr, size)
}
func (u *Usercorn) DirectWrite(addr uint64, p []byte) error {
	return u.Task.MemWrite(addr, p)
}

func (u *Usercorn) HookAdd(htype int, cb interface{}, begin, end uint64, extra ...int) (cpu.Hook, error) {
	hh, err := u.Cpu.HookAdd(htype, cb, begin, end, extra...)
	if err == nil {
		u.hooks = append(u.hooks, hh)
	}
	return hh, err
}

func (u *Usercorn) HookDel(hh cpu.Hook) error {
	tmp := make([]cpu.Hook, 0, len(u.hooks))
	for _, v := range u.hooks {
		if v != hh {
			tmp = append(tmp, v)
		}
	}
	u.hooks = tmp
	return u.Cpu.HookDel(hh)
}

func (u *Usercorn) HookSysAdd(before, after models.SysCb) *models.SysHook {
	hook := &models.SysHook{Before: before, After: after}
	u.sysHooks = append(u.sysHooks, hook)
	return hook
}

func (u *Usercorn) HookSysDel(hook *models.SysHook) {
	tmp := make([]*models.SysHook, 0, len(u.sysHooks)-1)
	for _, v := range u.sysHooks {
		if v != hook {
			tmp = append(tmp, v)
		}
	}
	u.sysHooks = tmp
}

func (u *Usercorn) Run() error {
	// TODO: defers are expensive I hear
	defer func() {
		if u.trace != nil && u.exitStatus == nil {
			u.trace.OnExit()
		}
		if u.trace != nil {
			u.trace.Detach()
		}
		if u.replay != nil {
			u.replay.Flush()
		}
		for _, v := range u.hooks {
			u.HookDel(v)
		}
		if e := recover(); e != nil {
			msg := fmt.Sprintf("\n+++ caught panic +++\n%s\n\n", e)
			if u.ui == nil {
				// FIXME: replay and task should be api-compatible, so we can pass a cpu in here instead
				if u.replay == nil {
					u.replay = trace.NewReplay(u.arch, u.os, u.Loader().ByteOrder(), u.debug)
				}
				u.ui = ui.NewStreamUI(u.config, u.replay)
			}
			u.ui.OnExit(false, msg)
			panic(e)
		}
	}()
	// PrefixArgs was added for shebang
	if len(u.config.PrefixArgs) > 0 {
		u.config.Args = append(u.config.PrefixArgs, u.config.Args...)
	}
	// TODO: hooks are removed below but if Run() is called again the OS stack will be reinitialized
	// maybe won't be a problem if the stack is zeroed and stack pointer is reset?
	// or OS stack init can be moved somewhere else (like NewUsercorn)
	if u.os.Init != nil {
		if err := u.os.Init(u, u.config.Args, u.config.Env); err != nil {
			return err
		}
	}
	if u.config.Trace.Any() {
		if err := u.trace.Attach(); err != nil {
			return err
		}
	}
	if err := u.addHooks(); err != nil {
		return err
	}
	if u.config.InsCount {
		u.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
			u.inscount++
		}, 1, 0)
	}
	if u.ui != nil {
		u.ui.OnStart(u.entry)
	}
	// in case this isn't the first run
	u.exitStatus = nil
	// loop to restart Cpu if we need to call a trampoline function
	u.RegWrite(u.arch.PC, u.entry)
	var err error
	for err == nil && u.exitStatus == nil {
		// well there's a huge pile of sync here to make sure everyone's ready to go...
		u.gate.Start()
		// allow a repl to break us out with u.Exit() before we run
		if u.exitStatus != nil {
			break
		}
		// allow repl or rewind to change pc
		pc, _ := u.RegRead(u.arch.PC)
		err = u.Start(pc, u.exit)
		u.gate.Stop()

		if u.restart != nil {
			err = u.restart(u, err)
			u.restart = nil
			if err != nil {
				break
			}
		}
		pc, _ = u.RegRead(u.arch.PC)
		if len(u.trampolines) > 0 {
			sp, _ := u.RegRead(u.arch.SP)
			trampolines := u.trampolines
			u.trampolines = nil
			// TODO: trampolines should be annotated in trace
			// trampolines should show up during symbolication?
			// FIXME: binary tracer does NOT handle this yet
			u.trampolined = true
			for _, tramp := range trampolines {
				if err = tramp.fun(); err != nil {
					break
				}
			}
			u.trampolined = false
			u.RegWrite(u.arch.PC, pc)
			u.RegWrite(u.arch.SP, sp)
		}
	}
	if _, ok := err.(models.ExitStatus); !ok && err != nil || u.config.Verbose {
		if u.ui != nil {
			if err != nil {
				u.ui.OnExit(false, err.Error())
			} else {
				u.ui.OnExit(false, "")
			}
		}
	}
	if u.config.InsCount {
		u.Printf("inscount: %d\n", u.inscount)
	}
	if err == nil && u.exitStatus != nil {
		err = u.exitStatus
	}
	return err
}

func (u *Usercorn) Gate() *models.Gate {
	return &u.gate
}

func (u *Usercorn) Start(pc, end uint64) error {
	u.running = true
	err := u.Cpu.Start(pc, end)
	u.running = false
	return err
}

func (u *Usercorn) Exe() string {
	return u.exe
}

func (u *Usercorn) Loader() models.Loader {
	return u.loader
}

func (u *Usercorn) InterpBase() uint64 {
	// points to interpreter base or 0
	return u.interpBase
}

func (u *Usercorn) Base() uint64 {
	// points to program base
	return u.base
}

func (u *Usercorn) Entry() uint64 {
	// points to effective program entry: either an interpreter or the binary
	return u.entry
}

func (u *Usercorn) SetEntry(entry uint64) {
	u.entry = entry
}

func (u *Usercorn) SetExit(exit uint64) {
	u.exit = exit
}

func (u *Usercorn) BinEntry() uint64 {
	// points to binary entry, even if an interpreter is used
	return u.binEntry
}

func (u *Usercorn) PrefixPath(path string, force bool) string {
	return u.config.PrefixPath(path, force)
}

func (u *Usercorn) Brk(addr uint64) (uint64, error) {
	// TODO: brk(0) behavior is linux specific
	cur := u.brk
	if addr > 0 && addr >= cur {
		// take brk protections from last brk segment (not sure if this is right)
		prot := cpu.PROT_READ | cpu.PROT_WRITE
		if brk := u.mapping(cur, 1); brk != nil {
			prot = brk.Prot
			u.brk = brk.Addr + brk.Size
		}
		size := addr - u.brk
		if size > 0 {
			_, err := u.Mmap(u.brk, size, prot, true, "brk", nil)
			if err != nil {
				return u.brk, err
			}
		}
		u.brk = addr
	}
	return u.brk, nil
}

func (u *Usercorn) addHooks() error {
	// TODO: this sort of error should be handled in ui module?
	// issue #244
	invalid := cpu.HOOK_MEM_ERR
	u.HookAdd(invalid, func(_ cpu.Cpu, access int, addr uint64, size int, value int64) bool {
		switch access {
		case cpu.MEM_WRITE_UNMAPPED, cpu.MEM_WRITE_PROT:
			u.Printf("invalid write")
		case cpu.MEM_READ_UNMAPPED, cpu.MEM_READ_PROT:
			u.Printf("invalid read")
		case cpu.MEM_FETCH_UNMAPPED, cpu.MEM_FETCH_PROT:
			u.Printf("invalid fetch")
		default:
			u.Printf("unknown memory error")
		}
		u.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, uint64(value))
		return false
	}, 1, 0)
	u.HookAdd(cpu.HOOK_INTR, func(_ cpu.Cpu, intno uint32) {
		u.os.Interrupt(u, intno)
	}, 1, 0)
	return nil
}

func (u *Usercorn) mapBinary(f *os.File, isInterp bool) (interpBase, entry, base, realEntry uint64, err error) {
	l := u.loader
	if isInterp {
		l, err = loader.LoadArch(f, l.Arch())
		if err != nil {
			return
		}
		u.interpLoader = l
	}
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
	// find segment bounds
	segments, err := l.Segments()
	if err != nil {
		return
	}
	low := ^uint64(0)
	high := uint64(0)
	for _, seg := range segments {
		if seg.Size == 0 {
			continue
		}
		if seg.Addr < low {
			low = seg.Addr
		}
		h := seg.Addr + seg.Size
		if h > high {
			high = h
		}
	}
	if low > high {
		low = high
	}
	// map contiguous binary
	loadBias := u.config.ForceBase
	if isInterp {
		loadBias = u.config.ForceInterpBase
		// reserve space at end of bin for brk
		barrier := u.brk + 8*1024*1024
		if loadBias <= barrier {
			loadBias = barrier
		}
	}
	if dynamic {
		mapLow := low
		if loadBias > 0 {
			mapLow = loadBias
		} else if mapLow == 0 {
			mapLow = 0x1000000
		}
		// TODO: is allocating the whole lib width remotely sane?
		var page *cpu.Page
		page, err = u.MemReserve(mapLow, high-low, false)
		if err != nil {
			return
		}
		loadBias = page.Addr - low
	}
	var desc string
	if isInterp {
		desc = "interp"
	} else {
		desc = "exe"
	}
	// initial forced segment mappings
	for _, seg := range segments {
		prot := seg.Prot
		if prot == 0 {
			// TODO: confirm why darwin needs this
			prot = cpu.PROT_ALL
		}
		fileDesc := &cpu.FileDesc{Name: f.Name(), Off: seg.Off, Len: seg.Size}
		_, err = u.Mmap(loadBias+seg.Addr, seg.Size, prot, true, desc, fileDesc)
		if err != nil {
			return
		}
	}
	// merge overlapping segments when writing contents to memory
	merged := make([]*models.Segment, 0, len(segments))
outer:
	for _, seg := range segments {
		if seg.Size == 0 {
			continue
		}
		addr, size := align(seg.Addr, seg.Size, true)
		s := &models.Segment{Start: addr, End: addr + size, Prot: seg.Prot}
		for _, s2 := range merged {
			if s2.Overlaps(s) {
				s2.Merge(s)
				continue outer
			}
		}
		merged = append(merged, s)
	}
	// write segment memory
	var data []byte
	for _, seg := range segments {
		if data, err = seg.Data(); err != nil {
			return
		}
		if err = u.MemWrite(loadBias+seg.Addr, data); err != nil {
			return
		}
	}
	entry = loadBias + l.Entry()
	// load interpreter if present
	interp := l.Interp()
	if interp != "" && !isInterp && !u.config.SkipInterp {
		f, err = os.Open(u.PrefixPath(interp, true))
		if err != nil {
			return
		}
		defer f.Close()
		u.brk = high
		var interpBias, interpEntry uint64
		_, _, interpBias, interpEntry, err = u.mapBinary(f, true)
		if u.interpLoader.Arch() != l.Arch() {
			err = errors.Errorf("Interpreter arch mismatch: %s != %s", l.Arch(), u.interpLoader.Arch())
			return
		}
		return interpBias, interpEntry, loadBias, entry, err
	} else {
		return 0, entry, loadBias, entry, nil
	}
}

func (u *Usercorn) MapStack(base, size uint64, guard bool) error {
	u.StackBase = base
	u.StackSize = size
	// TODO: check for NX stack?
	addr, err := u.Mmap(base, size, cpu.PROT_ALL, true, "stack", nil)
	if err != nil {
		return err
	}
	stackEnd := addr + size
	if err := u.RegWrite(u.arch.SP, stackEnd); err != nil {
		return err
	}
	if guard {
		_, err := u.Mmap(stackEnd, UC_MEM_ALIGN, cpu.PROT_NONE, true, "stack guard", nil)
		return err
	}
	return nil
}

func (u *Usercorn) AddKernel(kernel interface{}, first bool) {
	kco := kernel.(co.Kernel)
	if first {
		u.kernels = append([]co.Kernel{kco}, u.kernels...)
	} else {
		u.kernels = append(u.kernels, kco)
	}
}

func (u *Usercorn) Syscall(num int, name string, getArgs models.SysGetArgs) (uint64, error) {
	if name == "" {
		msg := fmt.Sprintf("Syscall missing: %d", num)
		if u.config.StubSyscalls {
			u.Println(msg)
		} else {
			panic(msg)
		}
	}
	if u.config.BlockSyscalls {
		return 0, nil
	}
	for _, k := range u.kernels {
		if sys := co.Lookup(u, k, name); sys != nil {
			args, err := getArgs(len(sys.In))
			if err != nil {
				return 0, err
			}
			desc := sys.Trace(args)
			prevent := false
			for _, v := range u.sysHooks {
				if v.Before(num, name, args, 0, desc) {
					prevent = true
				}
			}
			if prevent {
				return 0, nil
			}
			ret := sys.Call(args)
			desc = sys.TraceRet(args, ret)
			for _, v := range u.sysHooks {
				v.After(num, name, args, ret, desc)
			}
			return ret, nil
		}
	}
	// TODO: hook unknown syscalls?
	msg := errors.Errorf("Kernel not found for syscall '%s'", name)
	if u.config.StubSyscalls {
		u.Println(msg)
		return 0, nil
	} else {
		panic(msg)
	}
}

func (u *Usercorn) Exit(err error) {
	u.exitStatus = err
	u.Stop()
	if u.trace != nil {
		u.trace.OnExit()
	}
}

func (u *Usercorn) Close() error {
	var err error
	u.final.Do(func() {
		err = u.Cpu.Close()
	})
	return err
}

func (u *Usercorn) Mem() memio.MemIO {
	return u.memio
}

func (u *Usercorn) StrucAt(addr uint64) *models.StrucStream {
	options := &struc.Options{
		Order:   u.ByteOrder(),
		PtrSize: int(u.Bits()),
	}
	return models.NewStrucStream(u.Mem().StreamAt(addr), options)
}

func (u *Usercorn) Config() *models.Config { return u.config }

func (u *Usercorn) Printf(f string, args ...interface{}) { fmt.Fprintf(u.config.Output, f, args...) }
func (u *Usercorn) Println(s ...interface{})             { fmt.Fprintln(u.config.Output, s...) }

func (u *Usercorn) Restart(fn func(models.Usercorn, error) error) {
	u.restart = fn
	u.Stop()
}

func (u *Usercorn) Trampoline(fun func() error) error {
	if u.running {
		desc := ""
		if _, file, line, ok := runtime.Caller(1); ok {
			desc = fmt.Sprintf("%s:%d", file, line)
		}
		u.trampolines = append(u.trampolines, tramp{
			desc: desc,
			fun:  fun,
		})
		return u.Stop()
	} else {
		return fun()
	}
}

// like RunShellcode but you're expected to map memory yourself
func (u *Usercorn) RunShellcodeMapped(addr uint64, code []byte, setRegs map[int]uint64, regsClobbered []int) error {
	return u.Trampoline(func() error {
		if regsClobbered == nil {
			regsClobbered = make([]int, len(setRegs))
			pos := 0
			for reg := range setRegs {
				regsClobbered[pos] = reg
				pos++
			}
		}
		// save clobbered regs
		savedRegs := make([]uint64, len(regsClobbered))
		for i, reg := range regsClobbered {
			savedRegs[i], _ = u.RegRead(reg)
		}
		// defer restoring saved regs
		defer func() {
			for i, reg := range regsClobbered {
				u.RegWrite(reg, savedRegs[i])
			}
		}()
		// set setRegs
		for reg, val := range setRegs {
			u.RegWrite(reg, val)
		}
		if err := u.MemWrite(addr, code); err != nil {
			return err
		}
		return u.Start(addr, addr+uint64(len(code)))
	})
}

// maps and runs shellcode at addr
// if regsClobbered is nil, setRegs will be saved/restored
// if addr is 0, we'll pick one for you
// if addr is already mapped, we will return an error
// so non-PIE is your problem
// will trampoline if unicorn is already running
func (u *Usercorn) RunShellcode(addr uint64, code []byte, setRegs map[int]uint64, regsClobbered []int) error {
	size := uint64(len(code))
	exists := u.mapping(addr, size)
	if addr != 0 && exists != nil {
		return errors.Errorf("RunShellcode: 0x%x - 0x%x overlaps mapped memory", addr, addr+uint64(len(code)))
	}
	mapped, err := u.Mmap(addr, size, cpu.PROT_ALL, true, "shellcode", nil)
	if err != nil {
		return err
	}
	defer u.Trampoline(func() error {
		return u.MemUnmap(mapped, size)
	})
	return u.RunShellcodeMapped(mapped, code, setRegs, regsClobbered)
}

// like RunShellcode, but we assemble it for you
func (u *Usercorn) RunAsm(addr uint64, asm string, setRegs map[int]uint64, regsClobbered []int) error {
	// the assembler needs to know where the code is being assembled
	// the mapper needs to know how much memory to return
	// so we potentially bounce back and forth in a loop
	// in practice, this will never take more than one iteration, as we round up to page size
	// but maybe in the future there will be an allocator
	var code []byte
	var page *cpu.Page
	var err error
	for i := 0; ; i++ {
		if i > 100 {
			return errors.Errorf("RunAsm() took too many tries (>%d) to map memory", i)
		}
		code, err = u.Asm(asm, addr)
		if err != nil {
			return err
		}
		if len(code) == 0 {
			return errors.Errorf("RunAsm() assembled code was empty: %s\n", asm)
		}
		page, err = u.MemReserve(addr, uint64(len(code)), false)
		if err != nil {
			return err
		}
		// exit loop if there was space at our requested addr
		if page.Addr == addr {
			break
		}
		// FIXME: there's no "unreserve" function, and unmap is more expensive
		u.MemUnmap(page.Addr, page.Size)
		addr = page.Addr
	}
	if err := u.MemMap(page.Addr, page.Size, cpu.PROT_READ|cpu.PROT_EXEC); err != nil {
		return err
	}
	defer u.Trampoline(func() error {
		return u.MemUnmap(page.Addr, page.Size)
	})
	return u.RunShellcodeMapped(page.Addr, code, setRegs, regsClobbered)
}

var breakRe = regexp.MustCompile(`^((?P<addr>0x[0-9a-fA-F]+|\d+)|(?P<sym>[\w:]+(?P<off>\+0x[0-9a-fA-F]+|\d+)?)|(?P<source>.+):(?P<line>\d+))(@(?P<file>.+))?$`)

// adds a breakpoint to Usercorn instance
// see models.Breakpoint for desc syntax
// future=true adds it to the list of breakpoints to update when new memory is mapped/registered
func (u *Usercorn) BreakAdd(desc string, future bool, cb func(u models.Usercorn, addr uint64)) (*models.Breakpoint, error) {
	b, err := models.NewBreakpoint(desc, cb, u)
	if err != nil {
		return nil, err
	}
	u.breaks = append(u.breaks, b)
	if future {
		u.futureBreaks = append(u.futureBreaks, b)
	}
	return b, b.Apply()
}

// TODO: do these sort of operations while holding a lock?
func (u *Usercorn) BreakDel(b *models.Breakpoint) error {
	tmp := make([]*models.Breakpoint, 0, len(u.breaks))
	for _, v := range u.breaks {
		if v != b {
			tmp = append(tmp, v)
		}
	}
	u.breaks = tmp

	tmp = make([]*models.Breakpoint, 0, len(u.futureBreaks))
	for _, v := range u.futureBreaks {
		if v != b {
			tmp = append(tmp, v)
		}
	}
	u.futureBreaks = tmp

	return b.Remove()
}

func (u *Usercorn) Breakpoints() []*models.Breakpoint {
	return u.breaks
}

func (u *Usercorn) Symbolicate(addr uint64, includeSource bool) (*models.Symbol, string) {
	return u.debug.Symbolicate(addr, u.Task.Mappings(), includeSource)
}
