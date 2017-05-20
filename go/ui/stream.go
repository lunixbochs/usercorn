package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/trace"
)

func pad(s string, to int) string {
	if len(s) >= to {
		return ""
	}
	return strings.Repeat(" ", to-len(s))
}

type StreamUI struct {
	replay *trace.Replay
	config *models.Config
	regfmt string
	inscol int
	regcol int
	// pending is an OpStep representing the last unflushed instruction. Cleared by Flush().
	pending *trace.OpStep
	effects []models.Op
}

func NewStreamUI(c *models.Config, r *trace.Replay) *StreamUI {
	// find the longest register name
	longest := 0
	for _, name := range r.Arch.RegNames() {
		if len(name) > longest {
			longest = len(name)
		}
	}
	return &StreamUI{
		replay: r,
		config: c,
		regfmt: fmt.Sprintf("%%%ds = %%#0%dx", longest, r.Arch.Bits/4),
		inscol: 60, // FIXME
		regcol: longest + 5 + r.Arch.Bits/4,
	}
}

func (s *StreamUI) Feed(op models.Op, effects []models.Op) {
	switch o := op.(type) {
	case *trace.OpJmp:
	case *trace.OpStep:
		s.insPrint(s.replay.PC, o.Size, effects)
	case *trace.OpSyscall:
		s.sysPrint(o)
	}
}

// blockPrint() takes a basic block address to pretty-print
func (s *StreamUI) blockPrint(addr uint64) {
	fmt.Fprintf(s.config.Output, "\n%#x\n", addr)
}

// sysPrint() takes a syscall op to pretty-print
func (s *StreamUI) sysPrint(op *trace.OpSyscall) {
	// This is a workaround for live tracing.
	// Desc is not serialized so offline traces won't have access to it.
	if op.Desc != "" {
		fmt.Fprintln(s.config.Output, op.Desc)
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
		fmt.Fprintf(s.config.Output, "syscall(%d, [%s]) = %d\n", op.Num, strings.Join(args, ", "), op.Ret)
	}
}

// insPrint() takes an instruction address and side-effects to pretty-print
func (s *StreamUI) insPrint(pc uint64, size uint8, effects []models.Op) {
	// TODO: make all of this into Sprintf columns, and align the columns

	var ins string
	insmem := make([]byte, size)
	s.replay.Mem.Read(pc, insmem, 0)
	// TODO: disBytes setting?
	dis, err := models.Disas(insmem, pc, s.replay.Arch, s.config.DisBytes)
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
			name, ok := s.replay.Arch.RegNames()[int(o.Num)]
			if !ok {
				name = strconv.Itoa(int(o.Num))
			}
			reg := fmt.Sprintf(s.regfmt, name, o.Val)
			regs = append(regs, reg)
		case *trace.OpSpReg:
			fmt.Fprintf(s.config.Output, "<unimplemented special register>\n")
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
		fmt.Fprintf(s.config.Output, "%s | %s\n", ins, reg)
	} else {
		fmt.Fprintf(s.config.Output, "%s | %s | %s\n", ins, reg, m)
	}

	// print extra effects
	if len(regs) > 1 {
		inspad := strings.Repeat(" ", s.inscol)
		for i, r := range regs[1:] {
			if i+1 < len(mem) {
				fmt.Fprintf(s.config.Output, "%s + %s + %s\n", inspad, r, mem[i+1])
			} else {
				fmt.Fprintf(s.config.Output, "%s + %s\n", inspad, r)
			}
		}
	}
}
