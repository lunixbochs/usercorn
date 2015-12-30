package usercorn

import (
	"errors"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/lunixbochs/usercorn/go/arch"
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

type Config struct {
	Demangle        bool
	ForceBase       uint64
	ForceInterpBase uint64
	LoadPrefix      string
	LoopCollapse    int
	TraceExec       bool
	TraceMatch      []string
	TraceMatchDepth int
	TraceMem        bool
	TraceMemBatch   bool
	TraceReg        bool
	TraceSys        bool
	Verbose         bool
}

type Usercorn struct {
	*Unicorn
	config       Config
	exe          string
	loader       models.Loader
	interpLoader models.Loader
	kernels      []common.Kernel
	mappedFiles  []*models.MappedFile

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
}

func NewUsercorn(exe string, config *Config) (*Usercorn, error) {
	if config == nil {
		config = &Config{}
	}
	f, err := os.Open(exe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	l, err := loader.Load(f)
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
	exe, _ = filepath.Abs(exe)
	u := &Usercorn{
		Unicorn:       unicorn,
		exe:           exe,
		loader:        l,
		traceMatching: true,
		config:        *config,
	}
	// load kernels
	// the array cast is a trick to work around circular imports
	if os.Kernels != nil {
		kernelI := os.Kernels(u)
		kernels := make([]common.Kernel, len(kernelI))
		for i, k := range kernelI {
			kernels[i] = k.(common.Kernel)
		}
		u.kernels = kernels
	}
	// map binary (and interp) into memory
	u.status = models.StatusDiff{U: u, Color: true}
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
	if u.config.LoopCollapse > 0 {
		u.blockloop = models.NewLoopDetect(u.config.LoopCollapse)
	}
	if err := u.addHooks(); err != nil {
		return err
	}
	if err := u.mapStack(); err != nil {
		return err
	}
	if u.os.Init != nil {
		if err := u.os.Init(u, args, env); err != nil {
			return err
		}
	}
	if u.config.Verbose {
		fmt.Fprintf(os.Stderr, "[entry @ 0x%x]\n", u.entry)
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
		fmt.Fprintf(os.Stderr, "[stack @ 0x%x]\n", sp)
		for _, line := range models.HexDump(sp, buf[:], u.arch.Bits) {
			fmt.Fprintf(os.Stderr, "%s\n", line)
		}
	}
	if u.config.Verbose || u.config.TraceReg {
		u.status.Changes().Print("", true, false)
	}
	if u.config.Verbose {
		fmt.Fprintln(os.Stderr, "=====================================")
		fmt.Fprintln(os.Stderr, "==== Program output begins here. ====")
		fmt.Fprintln(os.Stderr, "=====================================")
	}
	if u.config.TraceReg || u.config.TraceExec {
		sp, _ := u.RegRead(u.arch.SP)
		u.stacktrace.Update(u.entry, sp)
	}
	if u.config.TraceMemBatch {
		u.memlog = *models.NewMemLog(u.ByteOrder())
	}
	err := u.Unicorn.Start(u.entry, 0xffffffffffffffff)
	if u.config.TraceMemBatch && !u.memlog.Empty() {
		u.memlog.Print("", u.arch.Bits)
		u.memlog.Reset()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Registers:")
		u.status.Changes().Print("", true, false)
		fmt.Fprintln(os.Stderr, "Stacktrace:")
		pc, _ := u.RegRead(u.arch.PC)
		sp, _ := u.RegRead(u.arch.SP)
		for _, frame := range u.stacktrace.Freeze(pc, sp) {
			fmt.Printf("  %s\n", frame.Pretty(u))
		}
	}
	if err == nil && u.exitStatus != nil {
		err = u.exitStatus
	}
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
	if filepath.IsAbs(path) && u.config.LoadPrefix != "" {
		target := filepath.Join(u.config.LoadPrefix, path)
		_, err := os.Stat(target)
		exists := !os.IsNotExist(err)
		if force || exists {
			return target
		}
	}
	return path
}

func (u *Usercorn) RegisterAddr(f *os.File, addr, size uint64, off int64) {
	l, err := loader.Load(f)
	if err != nil {
		return
	}
	symbols, _ := l.Symbols()
	DWARF, _ := l.DWARF()
	u.mappedFiles = append(u.mappedFiles, &models.MappedFile{
		Name:    path.Base(f.Name()),
		Off:     off,
		Addr:    addr,
		Size:    size,
		Symbols: symbols,
		DWARF:   DWARF,
	})
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
					fmt.Fprintf(os.Stderr, indent+"- (%d) loops over %s\n", count, chain)
				}
			}
			if u.config.TraceMemBatch {
				u.memlog.Print(indent, u.arch.Bits)
				u.memlog.Reset()
			}
			if sp, err := u.RegRead(u.arch.SP); err == nil {
				u.stacktrace.Update(addr, sp)
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
			if !u.config.TraceExec && u.config.TraceReg {
				changes := u.status.Changes()
				if changes.Count() > 0 {
					fmt.Fprintln(os.Stderr, blockLine)
					changes.Print(indent, true, true)
				}
			} else {
				fmt.Fprintln(os.Stderr, blockLine)
			}
		})
	}
	if u.config.TraceExec {
		u.HookAdd(uc.HOOK_CODE, func(_ uc.Unicorn, addr uint64, size uint32) {
			if !u.traceMatching {
				return
			}
			indent := strings.Repeat("  ", u.stacktrace.Len())
			if u.config.TraceExec && u.blockloop == nil || u.blockloop.Loops == 0 {
				changes := u.status.Changes()
				dis, _ := u.Disas(addr, uint64(size))
				fmt.Fprintf(os.Stderr, "%s", indent+dis)
				if !u.config.TraceReg || changes.Count() == 0 {
					fmt.Fprintln(os.Stderr)
				} else {
					dindent := ""
					// TODO: I can count the max dis length in the block and reuse it here
					pad := 40 - len(dis)
					if pad > 0 {
						dindent = strings.Repeat(" ", pad)
					}
					changes.Print(dindent, true, true)
				}
			}
		})
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
				fmt.Fprintf(os.Stderr, memFmt, indent, letter, addr, value)
			}
			if u.config.TraceMemBatch {
				write := (letter == "W")
				if !(u.config.TraceExec || u.config.TraceReg) && !u.memlog.Adjacent(addr, value, size, write) {
					u.memlog.Print("", u.arch.Bits)
					u.memlog.Reset()
				}
				u.memlog.Update(addr, size, value, letter == "W")
			}
		})
	}
	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	u.HookAdd(invalid, func(_ uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		switch access {
		case uc.MEM_WRITE_UNMAPPED, uc.MEM_WRITE_PROT:
			fmt.Fprintf(os.Stderr, "invalid write")
		case uc.MEM_READ_UNMAPPED, uc.MEM_READ_PROT:
			fmt.Fprintf(os.Stderr, "invalid read")
		case uc.MEM_FETCH_UNMAPPED, uc.MEM_FETCH_PROT:
			fmt.Fprintf(os.Stderr, "invalid fetch")
		default:
			fmt.Fprintf(os.Stderr, "unknown memory error")
		}
		fmt.Fprintf(os.Stderr, ": @0x%x, 0x%x = 0x%x\n", addr, size, uint64(value))
		return false
	})
	u.HookAdd(uc.HOOK_INTR, func(_ uc.Unicorn, intno uint32) {
		u.os.Interrupt(u, intno)
	})
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
		loadBias, err = u.Mmap(mapLow, high-low)
		if err != nil {
			return
		}
		loadBias -= low
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
		size := seg.End - seg.Start
		if dynamic && seg.Start == 0 && loadBias == 0 {
			loadBias, err = u.Mmap(0x1000000, size)
			err = u.MemProtect(loadBias, size, seg.Prot)
		} else {
			err = u.MemMapProt(loadBias+seg.Start, seg.End-seg.Start, prot)
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
	if interp != "" && !isInterp {
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
	u.StackBase = stack
	stackEnd := stack + STACK_SIZE
	if err := u.RegWrite(u.arch.SP, stackEnd); err != nil {
		return err
	}
	return u.MemMapProt(stackEnd, UC_MEM_ALIGN, uc.PROT_NONE)
}

func (u *Usercorn) Syscall(num int, name string, getArgs func(n int) ([]uint64, error)) (uint64, error) {
	if name == "" {
		panic(fmt.Sprintf("Syscall missing: %d", num))
	}
	if u.config.TraceSys && u.stacktrace.Len() > 0 {
		fmt.Fprintf(os.Stderr, strings.Repeat("  ", u.stacktrace.Len()-1)+"s ")
	}
	for _, k := range u.kernels {
		if sys := k.UsercornSyscall(name); sys != nil {
			args, err := getArgs(len(sys.In))
			if err != nil {
				return 0, err
			}
			if u.config.TraceSys {
				sys.Trace(args)
			}
			ret := sys.Call(args)
			if u.config.TraceSys {
				sys.TraceRet(args, ret)
			}
			return ret, nil
		}
	}
	panic(fmt.Errorf("Kernel not found for syscall '%s'", name))
}

func (u *Usercorn) Exit(status int) {
	u.exitStatus = models.ExitStatus(status)
	u.Stop()
}
