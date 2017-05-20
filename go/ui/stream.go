package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
	"github.com/lunixbochs/usercorn/go/models/trace"
)

func pad(s string, to int) string {
	if len(s) >= to {
		return ""
	}
	return strings.Repeat(" ", to-len(s))
}

type StreamUI struct {
	Arch   *models.Arch
	OS     *models.OS
	Mem    *cpu.MemSim
	Regs   map[int]uint64
	SpRegs map[int][]byte
	PC, SP uint64

	c      *models.Config
	regfmt string
	inscol int
	regcol int
	// pending is an OpStep representing the last unflushed instruction. Cleared by Flush().
	pending *trace.OpStep
	effects []models.Op
}

func NewStreamUI(c *models.Config, arch *models.Arch, os *models.OS) *StreamUI {
	// find the longest register name
	longest := 0
	for _, name := range arch.RegNames() {
		if len(name) > longest {
			longest = len(name)
		}
	}
	return &StreamUI{
		Arch:   arch,
		OS:     os,
		Mem:    &cpu.MemSim{},
		Regs:   make(map[int]uint64),
		SpRegs: make(map[int][]byte),

		c:      c,
		regfmt: fmt.Sprintf("%%%ds = %%#0%dx", longest, arch.Bits/4),
		inscol: 60, // FIXME
		regcol: longest + 5 + arch.Bits/4,
	}
}

// update() applies state change(s) from op to the UI's internal state
func (s *StreamUI) update(op models.Op) {
	// TODO: mlog2 will be a basic block filter
	// all memory ops in a block are pushed to the end and combined using memlog
	switch o := op.(type) {
	case *trace.OpJmp:
		s.PC = o.Addr
	case *trace.OpStep:
		s.PC += uint64(o.Size)
	case *trace.OpReg:
		if int(o.Num) == s.Arch.SP {
			s.SP = o.Val
		}
		s.Regs[int(o.Num)] = o.Val
	case *trace.OpSpReg:
		s.SpRegs[int(o.Num)] = o.Val

	case *trace.OpMemMap: // memory updates
		s.Mem.Map(o.Addr, uint64(o.Size), int(o.Prot), o.Zero != 0)
	case *trace.OpMemUnmap:
		s.Mem.Unmap(o.Addr, uint64(o.Size))
	case *trace.OpMemWrite:
		s.Mem.Write(o.Addr, o.Data, 0)

	case *trace.OpSyscall:
		for _, v := range o.Ops {
			s.update(v)
		}
	}
}

// Feed() is the entry point handling Op structs.
// It calls update() and combines side-effects with instructions to be printed.
func (s *StreamUI) Feed(op models.Op) {
	var ops []models.Op
	switch o := op.(type) {
	case *trace.OpFrame:
		ops = o.Ops
	default:
		ops = []models.Op{op}

	case *trace.OpKeyframe:
		// we need to flush here, because the keyframe can change state we need to print
		s.Flush()
		// We only need the first keyframe for simple display (until we're doing rewind/ff)
		// but it probably doesn't hurt too much for now to always process keyframes... just don't print them
		for _, v := range o.Ops {
			s.update(v)
		}
		return
	}

	for _, op := range ops {
		// batch everything until we hit an OpJmp or OpStep
		// at that point, flush the last OpStep
		switch o := op.(type) {
		case *trace.OpJmp:
			s.Flush()
			// s.blockPrint(o.Addr)
			s.update(o)
		case *trace.OpStep:
			s.Flush()
			s.pending = o
		case *trace.OpSyscall:
			s.Flush()
			s.sysPrint(o)
		default:
			// queue everything else as side-effects
			s.effects = append(s.effects, op)
		}
	}
	// flush at end of frame too, so repl isn't an instruction behind when single stepping
	s.Flush()
}

// Flush prints and clears the currently queued instruction and side-effects
func (s *StreamUI) Flush() {
	if s.pending != nil {
		s.insPrint(s.PC, s.pending.Size, s.effects)
		s.update(s.pending)
		for _, op := range s.effects {
			s.update(op)
		}
		s.effects = s.effects[:0]
		s.pending = nil
	}
}

// blockPrint() takes a basic block address to pretty-print
func (s *StreamUI) blockPrint(addr uint64) {
	fmt.Fprintf(s.c.Output, "\n%#x\n", addr)
}

// sysPrint() takes a syscall op to pretty-print
func (s *StreamUI) sysPrint(op *trace.OpSyscall) {
	// This is a workaround for live tracing.
	// Desc is not serialized so offline traces won't have access to it.
	if op.Desc != "" {
		fmt.Fprintln(s.c.Output, op.Desc)
	} else {
		// FIXME: this is a regression, how do we strace?
		// I think I need to embed the strace string during trace
		// until I get a chance to rework the strace backend

		// SECOND THOUGHT
		// I just need to expose a method on models.OS to convert syscall number into name
		// then I should be able to use the strace from kernel common
		// except I need to be able to dependency-inject the MemIO (as we might be on MemSim)
		args := make([]string, len(op.Args))
		for i, v := range op.Args {
			args[i] = fmt.Sprintf("%#x", v)
		}
		fmt.Fprintf(s.c.Output, "syscall(%d, [%s]) = %d\n", op.Num, strings.Join(args, ", "), op.Ret)
	}
}

// insPrint() takes an instruction address and side-effects to pretty-print
func (s *StreamUI) insPrint(pc uint64, size uint8, effects []models.Op) {
	// TODO: make all of this into Sprintf columns, and align the columns

	var ins string
	insmem := make([]byte, size)
	s.Mem.Read(pc, insmem, 0)
	// TODO: disBytes setting?
	dis, err := models.Disas(insmem, pc, s.Arch, false)
	if err != nil {
		ins = fmt.Sprintf("%#x: %x", pc, insmem)
	} else {
		ins = fmt.Sprintf("%s", dis)
	}

	// collect effects (should just be memory IO and register changes)
	var regs []string
	var mem []string
	for _, op := range effects {
		switch o := op.(type) {
		case *trace.OpReg:
			// FIXME: cache reg names as a list
			name, ok := s.Arch.RegNames()[int(o.Num)]
			if !ok {
				name = strconv.Itoa(int(o.Num))
			}
			reg := fmt.Sprintf(s.regfmt, name, o.Val)
			regs = append(regs, reg)
		case *trace.OpSpReg:
			fmt.Fprintf(s.c.Output, "<unimplemented special register>\n")
		case *trace.OpMemRead:
			// TODO: hexdump -C
			mem = append(mem, fmt.Sprintf("R %x", o.Addr))
		case *trace.OpMemWrite:
			// TODO: hexdump -C
			mem = append(mem, fmt.Sprintf("W %x", o.Addr))
		}
	}

	var reg, m string
	if len(regs) > 0 {
		reg = regs[0] + pad(regs[0], s.regcol)
	} else {
		reg = strings.Repeat(" ", s.regcol)
	}
	if len(mem) > 0 {
		m = mem[0]
	}
	ins += pad(ins, s.inscol)
	// TODO: remove dword, etc from x86 disassembly?
	// generally simplifying disassembly would improve the output
	// mov eax, dword ptr [eax + 8]
	// -> mov eax, [eax+8]
	//
	// 0x1004: mov eax, 1                   | eax = 1
	// 0x1008: mov eax, dword ptr [eax + 8] | eax = 2 |R 0x1020 0011 2233 4455 6677 [........]
	if m == "" {
		fmt.Fprintf(s.c.Output, "%s | %s\n", ins, reg)
	} else {
		fmt.Fprintf(s.c.Output, "%s | %s | %s\n", ins, reg, m)
	}

	// print extra effects
	if len(regs) > 1 {
		inspad := strings.Repeat(" ", s.inscol)
		for i, r := range regs[1:] {
			if i+1 < len(mem) {
				fmt.Fprintf(s.c.Output, "%s + %s + %s\n", inspad, r, mem[i+1])
			} else {
				fmt.Fprintf(s.c.Output, "%s + %s\n", inspad, r)
			}
		}
	}
}
