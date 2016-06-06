package usercorn

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/lunixbochs/ghostrace/ghost/memio"
	"github.com/lunixbochs/readline"
	"github.com/lunixbochs/struc"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lunixbochs/usercorn/go/arch"
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

type tramp struct {
	desc string
	fun  func() error
}

type Usercorn struct {
	*Unicorn
	config       *models.Config
	exe          string
	loader       models.Loader
	interpLoader models.Loader
	kernels      []co.Kernel
	mappedFiles  []*models.MappedFile
	memio        memio.MemIO

	base       uint64
	interpBase uint64
	entry      uint64
	binEntry   uint64

	StackBase uint64
	brk       uint64

	traceMatching bool

	status     models.StatusDiff
	stacktrace models.Stacktrace
	blockloop  *models.LoopDetect
	memlog     models.MemLog

	exitStatus error
	insnCount  uint64

	running     bool
	trampolines []tramp
	trampolined bool
}

func NewUsercorn(exe string, config *models.Config) (models.Usercorn, error) {
	if config == nil {
		config = &models.Config{}
	}
	if config.Output == nil {
		config.Output = os.Stderr
	}
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
	a, OS, err := arch.GetArch(l.Arch(), l.OS())
	if err != nil {
		return nil, err
	}
	unicorn, err := NewUnicorn(a, OS, l.ByteOrder())
	if err != nil {
		return nil, err
	}
	exe, _ = filepath.Abs(exe)
	u := &Usercorn{
		Unicorn:       unicorn,
		exe:           exe,
		loader:        l,
		traceMatching: true,
		config:        config,
	}
	if config.Output == os.Stderr && readline.IsTerminal(int(os.Stderr.Fd())) {
		u.config.Color = true
	}
	u.memio = memio.NewMemIO(
		// ReadAt() callback
		func(p []byte, addr uint64) (int, error) {
			if err := u.MemReadInto(p, addr); err != nil {
				return 0, err
			}
			if u.config.TraceMemBatch {
				u.memlog.UpdateBytes(addr, p, false)
			}
			return len(p), nil
		},
		// WriteAt() callback
		func(p []byte, addr uint64) (int, error) {
			if err := u.MemWrite(addr, p); err != nil {
				return 0, err
			}
			if u.config.TraceMemBatch {
				u.memlog.UpdateBytes(addr, p, true)
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
	// map binary (and interp) into memory
	u.status = models.StatusDiff{U: u}
	u.interpBase, u.entry, u.base, u.binEntry, err = u.mapBinary(f, false, l.Arch())
	if err != nil {
		return nil, err
	}
	// find data segment for brk
	segments, err := l.Segments()
	if err != nil {
		return nil, err
	}
	for _, seg := range segments {
		if seg.Prot&uc.PROT_WRITE != 0 {
			addr := u.base + seg.Addr + seg.Size
			if addr > u.brk {
				u.brk = addr
			}
		}
	}
	// TODO: have a "host page size", maybe arch.Align()
	mask := uint64(4096 - 1)
	u.Brk((u.brk + mask) & ^mask)
	return u, nil
}

func (u *Usercorn) Run(args []string, env []string) error {
	// PrefixArgs was added for shebang
	if len(u.config.PrefixArgs) > 0 {
		args = append(u.config.PrefixArgs, args...)
	}
	if u.config.LoopCollapse > 0 {
		u.blockloop = models.NewLoopDetect(u.config.LoopCollapse)
	}
	if err := u.mapStack(); err != nil {
		return err
	}
	if u.os.Init != nil {
		if err := u.os.Init(u, args, env); err != nil {
			return err
		}
	}
	if err := u.addHooks(); err != nil {
		return err
	}
	if u.config.Verbose {
		u.Printf("[entry @ 0x%x]\n", u.entry)
		dis, err := u.Disas(u.entry, 64)
		if err != nil {
			u.Println(err)
		} else {
			u.Println(dis)
		}
		sp, err := u.RegRead(u.arch.SP)
		if err != nil {
			return err
		}
		buf := make([]byte, u.StackBase+STACK_SIZE-sp)
		if err := u.MemReadInto(buf, sp); err != nil {
			return err
		}
		u.Printf("[stack @ 0x%x]\n", sp)
		for _, line := range models.HexDump(sp, buf[:], u.arch.Bits) {
			u.Println(line)
		}
		u.Printf("[memory map]\n")
		for _, m := range u.Mappings() {
			u.Printf("  %v\n", m.String())
		}
	}
	if u.config.Verbose || u.config.TraceReg {
		u.Println(u.status.Changes().String("", u.config.Color, false))
	}
	if u.config.Verbose {
		u.Println("=====================================")
		u.Println("==== Program output begins here. ====")
		u.Println("=====================================")
	}
	if u.config.TraceBlock || u.config.TraceReg || u.config.TraceExec {
		sp, _ := u.RegRead(u.arch.SP)
		u.stacktrace.Update(u.entry, sp)
	}
	if u.config.TraceMemBatch {
		u.memlog = *models.NewMemLog(u.ByteOrder())
	}
	if u.config.SavePre != "" {
		u.RegWrite(u.arch.PC, u.entry)
		if err := u.save(u.config.SavePre); err != nil {
			u.Printf("failed to save pre-state: %s\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// handle savestate even under panic
	if u.config.SavePost != "" {
		defer func() {
			if err := u.save(u.config.SavePost); err != nil {
				u.Printf("failed to save post-state: %s\n", err)
			}
		}()
	}
	// panic/exit handler
	verboseExit := func() {
		u.Printf("[memory map]\n")
		for _, m := range u.Mappings() {
			u.Printf("  %v\n", m.String())
		}
		u.Println("[registers]")
		u.Printf("%s", u.status.Changes().String("", u.config.Color, false))
		u.Println("[stacktrace]")
		pc, _ := u.RegRead(u.arch.PC)
		sp, _ := u.RegRead(u.arch.SP)
		for _, frame := range u.stacktrace.Freeze(pc, sp) {
			u.Printf("  %s\n", frame.Pretty(u))
		}
	}
	defer func() {
		if e := recover(); e != nil {
			u.Printf("\n+++ panic dump +++\n")
			verboseExit()
			u.Printf("------------------\n\n")
			panic(e)
		}
	}()

	// loop to restart Unicorn if we need to call a trampoline function
	pc := u.entry
	var err error
	for err == nil {
		err = u.Start(pc, 0xffffffffffffffff)
		u.Printf("%s", u.memlog.Flush("", u.arch.Bits))
		if err != nil || len(u.trampolines) == 0 {
			break
		}
		pc, _ = u.RegRead(u.arch.PC)
		sp, _ := u.RegRead(u.arch.SP)
		trampolines := u.trampolines
		u.trampolines = nil
		// TODO: trampolines should be annotated in trace
		// trampolines should show up during symbolication?
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
	if err != nil || u.config.Verbose {
		verboseExit()
	}
	if err == nil && u.exitStatus != nil {
		err = u.exitStatus
	}
	return err
}

func (u *Usercorn) save(filename string) error {
	data, err := models.Save(u)
	if err == nil {
		err = ioutil.WriteFile(filename, data, 0644)
	}
	return err
}

func (u *Usercorn) Start(pc, end uint64) error {
	u.running = true
	err := u.Unicorn.Start(pc, end)
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

func (u *Usercorn) BinEntry() uint64 {
	// points to binary entry, even if an interpreter is used
	return u.binEntry
}

func (u *Usercorn) PrefixPath(path string, force bool) string {
	return u.config.PrefixPath(path, force)
}

func (u *Usercorn) RegisterAddr(f *os.File, addr, size uint64, off int64) {
	l, err := loader.Load(f)
	if err != nil {
		return
	}
	symbols, _ := l.Symbols()
	DWARF, _ := l.DWARF()
	mappedFile := &models.MappedFile{
		Name:    path.Base(f.Name()),
		Off:     off,
		Addr:    addr,
		Size:    size,
		Symbols: symbols,
		DWARF:   DWARF,
	}
	u.mappedFiles = append(u.mappedFiles, mappedFile)
	if mmap := u.mapping(addr, size); mmap != nil {
		mmap.File = mappedFile
	}
}

func (u *Usercorn) Symbolicate(addr uint64, includeFile bool) (string, error) {
	var sym models.Symbol
	var dist uint64
	fileLine := ""
	for _, f := range u.mappedFiles {
		if f.Contains(addr) {
			sym, dist = f.Symbolicate(addr)
			if sym.Name != "" && includeFile {
				fileLine = f.FileLine(addr)
			}
			break
		}
	}
	name := sym.Name
	if name != "" {
		if u.config.Demangle {
			name = models.Demangle(name)
		}
		if dist > 0 {
			name = fmt.Sprintf("%s+0x%x", name, dist)
		}
		if fileLine != "" {
			name = fmt.Sprintf("%s (%s)", name, fileLine)
		}
	}
	return name, nil
}

func (u *Usercorn) Brk(addr uint64) (uint64, error) {
	// TODO: this is linux specific
	if addr > 0 {
		err := u.MemMapProt(u.brk, addr-u.brk, uc.PROT_READ|uc.PROT_WRITE)
		if err != nil {
			return u.brk, err
		}
		if mmap := u.mapping(u.brk, addr); mmap != nil {
			mmap.Desc = "brk"
		}
		u.brk = addr
	}
	return u.brk, nil
}

func (u *Usercorn) checkTraceMatch(addr uint64, sym string) bool {
	if len(u.config.TraceMatch) == 0 {
		return true
	}
	match := func(addr uint64, sym string, trace string) bool {
		return sym == trace || strings.HasPrefix(sym, trace+"+") || fmt.Sprintf("0x%x", addr) == strings.ToLower(trace)
	}
	for _, v := range u.config.TraceMatch {
		if match(addr, sym, v) {
			return true
		}
	}
	l := u.stacktrace.Len()
	for i := 0; i < u.config.TraceMatchDepth && i < l; i++ {
		frame := u.stacktrace.Stack[l-i-1]
		for _, v := range u.config.TraceMatch {
			sym, _ := u.Symbolicate(frame.PC, false)
			if match(frame.PC, sym, v) {
				return true
			}
		}
	}
	return false
}

func (u *Usercorn) addHooks() error {
	if u.config.TraceBlock {
		u.HookAdd(uc.HOOK_BLOCK, func(_ uc.Unicorn, addr uint64, size uint32) {
			if !u.trampolined && !(u.config.TraceExec || u.config.TraceReg) {
				if sp, err := u.RegRead(u.arch.SP); err == nil {
					u.stacktrace.Update(addr, sp)
				}
			}
			u.Printf("0x%x %d %d\n", addr, size, u.stacktrace.Len())
		}, 1, 0)
	}
	if u.config.TraceExec || u.config.TraceReg {
		u.HookAdd(uc.HOOK_BLOCK, func(_ uc.Unicorn, addr uint64, size uint32) {
			sym, _ := u.Symbolicate(addr, false)
			if !u.checkTraceMatch(addr, sym) {
				u.traceMatching = false
				return
			}
			u.traceMatching = true
			var indent string
			if u.stacktrace.Len() > 2 {
				indent = strings.Repeat("  ", u.stacktrace.Len()-1)
			}
			if u.blockloop != nil {
				if looped, loop, count := u.blockloop.Update(addr); looped {
					return
				} else if count > 1 {
					// TODO: maybe print a message when we start collapsing loops
					// with the symbols or even all disassembly involved encapsulated
					chain := u.blockloop.String(u, loop)
					u.Printf(indent+"- (%d) loops over %s\n", count, chain)
				}
			}
			u.Printf("%s", u.memlog.Flush(indent, u.arch.Bits))
			if !u.trampolined {
				if sp, err := u.RegRead(u.arch.SP); err == nil {
					u.stacktrace.Update(addr, sp)
				}
			}
			indent = strings.Repeat("  ", u.stacktrace.Len())
			blockIndent := indent
			if len(indent) >= 2 {
				blockIndent = indent[:len(indent)-2]
			}
			if sym != "" {
				sym = " (" + sym + ")"
			}
			blockLine := fmt.Sprintf("\n%s+ block%s @0x%x", blockIndent, sym, addr)
			changes := u.status.Changes()
			if !u.config.TraceExec && u.config.TraceReg {
				// if only registers are being traced, we don't need to print
				// the block if no registers were modified
				if changes.Count() > 0 {
					u.Println(blockLine)
					u.Printf("%s", changes.String(indent, u.config.Color, true))
				}
			} else {
				if changes.Count() > 0 {
					u.Printf("%s", changes.String(blockIndent, u.config.Color, true))
				}
				u.Println(blockLine)
			}
		}, 1, 0)
	}
	if u.config.TraceExec {
		u.HookAdd(uc.HOOK_CODE, func(_ uc.Unicorn, addr uint64, size uint32) {
			u.insnCount++
			if !u.traceMatching {
				return
			}
			indent := strings.Repeat("  ", u.stacktrace.Len())
			if u.config.TraceExec && u.blockloop == nil || u.blockloop.Loops == 0 || u.trampolined {
				changes := u.status.Changes()
				dis, _ := u.Disas(addr, uint64(size))
				u.Printf("%s", indent+dis)
				if !u.config.TraceReg || changes.Count() == 0 {
					u.Println("")
				} else {
					dindent := ""
					// TODO: I can count the max dis length in the block and reuse it here
					pad := 40 - len(dis)
					if pad > 0 {
						dindent = strings.Repeat(" ", pad)
					}
					u.Printf("%s", changes.String(dindent, u.config.Color, true))
				}
			}
		}, 1, 0)
	}
	if u.config.TraceMem || u.config.TraceMemBatch {
		u.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(_ uc.Unicorn, access int, addr uint64, size int, value int64) {
			if !u.traceMatching {
				return
			}
			var letter string
			if access == uc.MEM_WRITE {
				letter = "W"
			} else {
				letter = "R"
				if data, err := u.MemRead(addr, uint64(size)); err == nil {
					e := u.ByteOrder()
					switch size {
					case 1:
						value = int64(data[0])
					case 2:
						value = int64(e.Uint16(data))
					case 4:
						value = int64(e.Uint32(data))
					case 8:
						value = int64(e.Uint64(data))
					}
				}
			}
			if u.config.TraceMem {
				memFmt := fmt.Sprintf("%%s%%s 0x%%0%dx 0x%%0%dx\n", u.Bsz*2, size*2)
				indent := ""
				if u.stacktrace.Len() > 0 {
					indent = strings.Repeat("  ", u.stacktrace.Len()-1)
				}
				u.Printf(memFmt, indent, letter, addr, value)
			}
			if u.config.TraceMemBatch {
				u.memlog.Update(addr, size, value, letter == "W")
			}
		}, 1, 0)
	}
	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	u.HookAdd(invalid, func(_ uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		switch access {
		case uc.MEM_WRITE_UNMAPPED, uc.MEM_WRITE_PROT:
			u.Printf("invalid write")
		case uc.MEM_READ_UNMAPPED, uc.MEM_READ_PROT:
			u.Printf("invalid read")
		case uc.MEM_FETCH_UNMAPPED, uc.MEM_FETCH_PROT:
			u.Printf("invalid fetch")
		default:
			u.Printf("unknown memory error")
		}
		u.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, uint64(value))
		return false
	}, 1, 0)
	u.HookAdd(uc.HOOK_INTR, func(_ uc.Unicorn, intno uint32) {
		u.os.Interrupt(u, intno)
	}, 1, 0)
	return nil
}

func (u *Usercorn) mapBinary(f *os.File, isInterp bool, arch string) (interpBase, entry, base, realEntry uint64, err error) {
	var l models.Loader
	l, err = loader.LoadArch(f, arch)
	if err != nil {
		return
	}
	if isInterp {
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
	var low, high uint64
	for _, seg := range segments {
		if seg.Addr < low {
			low = seg.Addr
		}
		h := seg.Addr + seg.Size
		if h > high {
			high = h
		}
	}
	// map contiguous binary
	loadBias := u.config.ForceBase
	if isInterp {
		loadBias = u.config.ForceInterpBase
	}
	if dynamic {
		mapLow := low
		if loadBias > 0 {
			mapLow = loadBias
		} else if mapLow == 0 {
			mapLow = 0x1000000
		}
		var mmap *models.Mmap
		mmap, err = u.Mmap(mapLow, high-low)
		if err != nil {
			return
		}
		loadBias = mmap.Addr - low
		if isInterp {
			mmap.Desc = "interp"
		} else {
			mmap.Desc = "exe"
		}
	}
	// merge overlapping segments
	merged := make([]*models.Segment, 0, len(segments))
outer:
	for _, seg := range segments {
		addr, size := align(seg.Addr, seg.Size, true)
		s := &models.Segment{addr, addr + size, seg.Prot}
		for _, s2 := range merged {
			if s2.Overlaps(s) {
				s2.Merge(s)
				continue outer
			}
		}
		merged = append(merged, s)
	}
	// map merged segments
	for _, seg := range merged {
		prot := seg.Prot
		if prot == 0 {
			prot = uc.PROT_ALL
		}
		if !dynamic {
			err = u.MemMapProt(loadBias+seg.Start, seg.End-seg.Start, prot)
			if mmap := u.mapping(loadBias+seg.Start, loadBias+seg.End); mmap != nil {
				mmap.Desc = "exe"
			}
		}
		// register binary for symbolication
		u.RegisterAddr(f, loadBias+seg.Start, seg.End-seg.Start, int64(seg.Start))
		if err != nil {
			return
		}
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
		var interpBias, interpEntry uint64
		_, _, interpBias, interpEntry, err = u.mapBinary(f, true, l.Arch())
		if u.interpLoader.Arch() != l.Arch() {
			err = fmt.Errorf("Interpreter arch mismatch: %s != %s", l.Arch(), u.interpLoader.Arch())
			return
		}
		return interpBias, interpEntry, loadBias, entry, err
	} else {
		return 0, entry, loadBias, entry, nil
	}
}

func (u *Usercorn) mapStack() error {
	stack, err := u.Mmap(STACK_BASE, STACK_SIZE)
	if err != nil {
		return err
	}
	stack.Desc = "stack"
	u.StackBase = stack.Addr
	stackEnd := stack.Addr + STACK_SIZE
	if err := u.RegWrite(u.arch.SP, stackEnd); err != nil {
		return err
	}
	return u.MemMapProt(stackEnd, UC_MEM_ALIGN, uc.PROT_NONE)
}

func (u *Usercorn) Syscall(num int, name string, getArgs func(n int) ([]uint64, error)) (uint64, error) {
	if name == "" {
		panic(fmt.Sprintf("Syscall missing: %d", num))
	}
	indent := ""
	if u.config.TraceSys && u.stacktrace.Len() > 0 {
		indent = strings.Repeat("  ", u.stacktrace.Len()-1)
		u.Printf("%s", u.memlog.Flush(indent, u.arch.Bits))
	}
	for _, k := range u.kernels {
		if sys := co.Lookup(u, k, name); sys != nil {
			args, err := getArgs(len(sys.In))
			if err != nil {
				return 0, err
			}
			if u.config.TraceSys {
				u.Printf(indent + "s ")
				u.Printf("%s", sys.Trace(args))
				// don't memlog our strace
				u.memlog.Reset()
			}
			ret := sys.Call(args)
			if u.config.TraceSys {
				// don't memlog ret either
				u.memlog.Freeze()
				// TODO: print this manually?
				u.Printf("%s", sys.TraceRet(args, ret))
			}
			u.Printf("%s", u.memlog.Flush(indent, u.arch.Bits))
			return ret, nil
		}
	}
	panic(fmt.Errorf("Kernel not found for syscall '%s'", name))
}

func (u *Usercorn) Exit(err error) {
	u.exitStatus = err
	u.Stop()
}

func (u *Usercorn) Mem() memio.MemIO {
	return u.memio
}

func (u *Usercorn) StrucAt(addr uint64) *models.StrucStream {
	options := &struc.Options{
		Order:   u.ByteOrder(),
		PtrSize: int(u.Bits()),
	}
	return &models.StrucStream{u.Mem().StreamAt(addr), options}
}

func (u *Usercorn) Config() *models.Config {
	return u.config
}

func (u *Usercorn) Printf(f string, args ...interface{}) {
	fmt.Fprintf(u.config.Output, f, args...)
}

func (u *Usercorn) Println(s interface{}) {
	u.Printf("%s\n", s)
}

func (u *Usercorn) trampoline(fun func() error) error {
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
func (u *Usercorn) RunShellcodeMapped(mmap *models.Mmap, code []byte, setRegs map[int]uint64, regsClobbered []int) error {
	return u.trampoline(func() error {
		if regsClobbered == nil {
			regsClobbered = make([]int, len(setRegs))
			pos := 0
			for reg, _ := range setRegs {
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
		if err := u.MemWrite(mmap.Addr, code); err != nil {
			return err
		}
		return u.Start(mmap.Addr, mmap.Addr+uint64(len(code)))
	})
}

// maps and runs shellcode at addr
// if regsClobbered is nil, setRegs will be saved/restored
// if addr is 0, we'll pick one for you
// if addr is already mapped, we will return an error
// so non-PIE is your problem
// will trampoline if unicorn is already running
func (u *Usercorn) RunShellcode(addr uint64, code []byte, setRegs map[int]uint64, regsClobbered []int) error {
	exists := u.mapping(addr, uint64(len(code)))
	if addr != 0 && exists != nil {
		return fmt.Errorf("RunShellcode: 0x%x - 0x%x overlaps mapped memory", addr, addr+uint64(len(code)))
	}
	mmap, err := u.Mmap(addr, uint64(len(code)))
	if err != nil {
		return err
	}
	defer u.trampoline(func() error {
		return u.MemUnmap(mmap.Addr, mmap.Size)
	})
	return u.RunShellcodeMapped(mmap, code, setRegs, regsClobbered)
}
