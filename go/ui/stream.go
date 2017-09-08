package ui

import (
	"fmt"
	"github.com/pkg/errors"
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

func (s *StreamUI) OnStart(entry uint64) {
	if !s.config.Verbose {
		return
	}
	s.Printf("[entry @ 0x%x]\n", entry)
	dis, err := s.dis(entry, 64)
	if err != nil {
		s.Println(err)
	} else {
		s.Println(dis)
	}
	sp := s.replay.SP
	buf := make([]byte, 128)
	if err := s.replay.Mem.MemReadInto(buf, sp-32); err != nil {
		s.Println("error reading stack:", err)
	} else {
		s.Println("[stack]")
		for _, line := range models.HexDump(sp-32, buf[:32], s.replay.Arch.Bits) {
			s.Println(line)
		}
	}
	s.Println("[stack pointer]")
	for _, line := range models.HexDump(sp, buf[32:], s.replay.Arch.Bits) {
		s.Println(line)
	}
	// TODO: annotate replay's maps with filename / mapping type (required for symbolication too)
	s.Println("[memory map]")
	for _, mm := range s.replay.Mem.Maps() {
		s.Printf("  %s\n", mm)
	}
	s.Println("=====================================")
	s.Println("==== Program output begins here. ====")
	s.Println("=====================================")
}

func (s *StreamUI) OnExit(clean bool, msg string) {
	if clean && !s.config.Verbose {
		return
	}
	if msg != "" {
		s.Println(msg)
	}
	dis, err := s.dis(s.replay.PC, 64)
	if err == nil {
		s.Println("[pc]")
		s.Println(dis)
	}
	// TODO: annotate replay's maps with filename / mapping type (required for symbolication too)
	s.Println("[memory map]")
	for _, mm := range s.replay.Mem.Maps() {
		s.Printf("  %s\n", mm)
	}
	s.Println("[registers]")
	// FIXME: cache reg names as a list
	names := s.replay.Arch.RegNames()
	for enum, val := range s.replay.Regs {
		name, ok := names[enum]
		if !ok {
			name = strconv.Itoa(enum)
		}
		s.Printf("%s: %#x\n", name, val)
	}
	// TODO: print stacktrace here
}

func (s *StreamUI) dis(addr, size uint64) (string, error) {
	mem, err := s.replay.Mem.MemRead(addr, uint64(size))
	if err != nil {
		return "", errors.Wrap(err, "dis() mem read failed")
	}
	return models.Disas(mem, addr, s.replay.Arch, s.config.DisBytes)
}

// blockPrint() takes a basic block address to pretty-print
func (s *StreamUI) blockPrint(addr uint64) {
	s.Printf("\n%#x\n", addr)
}

func (s *StreamUI) Printf(f string, args ...interface{}) { fmt.Fprintf(s.config.Output, f, args...) }
func (s *StreamUI) Println(args ...interface{})          { fmt.Fprintln(s.config.Output, args...) }

// sysPrint() takes a syscall op to pretty-print
func (s *StreamUI) sysPrint(op *trace.OpSyscall) {
	// This is a workaround for live tracing.
	// Desc is not serialized so offline traces won't have access to it.
	if op.Desc != "" {
		s.Println(op.Desc)
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
		s.Printf("syscall(%d, [%s]) = %d\n", op.Num, strings.Join(args, ", "), op.Ret)
	}
}

// insPrint() takes an instruction address and side-effects to pretty-print
func (s *StreamUI) insPrint(pc uint64, size uint8, effects []models.Op) {
	// TODO: make all of this into Sprintf columns, and align the columns

	var ins string
	dis, err := s.dis(pc, uint64(size))
	if err != nil {
		insmem, _ := s.replay.Mem.MemRead(pc, uint64(size))
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
			s.Println("<unimplemented special register>")
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
		s.Printf("%s | %s\n", ins, reg)
	} else {
		s.Printf("%s | %s | %s\n", ins, reg, m)
	}

	// print extra effects
	if len(regs) > 1 {
		inspad := strings.Repeat(" ", s.inscol)
		for i, r := range regs[1:] {
			if i+1 < len(mem) {
				s.Printf("%s + %s + %s\n", inspad, r, mem[i+1])
			} else {
				s.Printf("%s + %s\n", inspad, r)
			}
		}
	}
	for _, op := range effects {
		switch o := op.(type) {
		case *trace.OpMemBatch:
			s.Printf("%s", o.Render(s.replay.Mem))
		}
	}
}
