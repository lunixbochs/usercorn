package bpf

import (
	"encoding/binary"
	"fmt"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

const (
	M0 = iota
	M1
	M2
	M3
	M4
	M5
	M6
	M7
	M8
	M9
	M10
	M11
	M12
	M13
	M14
	M15
	A
	X
	PC
)

type Builder struct{}

func (b *Builder) New() (cpu.Cpu, error) {
	c := &BpfCpu{
		Regs: cpu.NewRegs(32, []int{
			M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10,
			M11, M12, M13, M14, M15, A, X, PC}),
		Mem: cpu.NewMem(32, binary.LittleEndian),
	}
	c.Hooks = cpu.NewHooks(c, c.Mem)
	return c, nil
}

type BpfCpu struct {
	*cpu.Hooks
	*cpu.Regs
	*cpu.Mem
}

func NewCpu() (cpu.Cpu, error) {
	c := &BpfCpu{
		Regs: cpu.NewRegs(32, []int{
			A, X, PC,
		}),
		Mem: cpu.NewMem(32, binary.LittleEndian),
	}
	c.Hooks = cpu.NewHooks(c, c.Mem)
	return c, nil
}

func (c *BpfCpu) get(a arg) uint32 {
	var val uint64
	switch v := a.(type) {
	case *regX:
		val, _ = c.RegRead(X)
	case *abs:
		val, _ = c.ReadUint(uint64(v.val), 4, 0)
	case *mem:
		val = uint64(v.val)
	case *ind:
		off, _ := c.RegRead(X)
		val, _ = c.ReadUint(uint64(v.val)+off, 4, 0)
	case *imm:
		val = uint64(v.val)
	case *msh:
		// TODO: How does this work for ldx?
		val, _ = c.ReadUint(uint64(v.val), 1, 0)
		val = uint64((val & 0xf) * 4)
	case *jabs:
		val = uint64(v.val)
	case *jelse:
		val = uint64(v.val)
	case *j:
		val = uint64(v.val)
	case *regA:
		val, _ = c.RegRead(A)
	default:
		panic("Unhandled arg")
	}
	return uint32(val)
}

// getJump gets the jump target offset in bytes
func (c *BpfCpu) getJump(a arg) uint32 {
	switch a := a.(type) {
	case *jabs:
		return uint32(a.val) * 8
	case *j:
		return uint32(a.jf) * 8
	case *jelse:
		return uint32(a.jf) * 8
	default:
		panic("Jump with illegal args!")
	}
}

// getJumpElse gets the jump else case offset in bytes
func (c *BpfCpu) getJumpElse(a arg) uint32 {
	switch a := a.(type) {
	case *j:
		return 0
	case *jelse:
		return uint32(a.jt) * 8
	default:
		panic("Jump with illegal args!")
	}
}

func (c *BpfCpu) Start(begin, until uint64) error {
	var dis Dis
	pc := uint32(begin)
	c.RegWrite(PC, uint64(pc))
	var err error

	for pc <= uint32(until) && err == nil {
		var mem []byte
		var code []models.Ins

		if mem, err = c.ReadProt(uint64(pc), 8, cpu.PROT_EXEC); err != nil {
			break
		}
		if code, err = dis.Dis(mem, uint64(pc)); err != nil {
			break
		}
		ins := code[0].(*ins)
		fmt.Printf("%04x: %s\n", pc, ins)

		c.OnCode(uint64(pc), uint32(len(ins.bytes)))

		jumpoff := uint32(0)
		al, _ := c.RegRead(A)
		a := uint32(al)
		xl, _ := c.RegRead(X)
		x := uint32(xl)

		switch ins.name {
		case "ret":
			err = fmt.Errorf("Returning value %#x", c.get(ins.arg))
		case "ld":
			fallthrough
		case "ldi":
			c.RegWrite(A, uint64(c.get(ins.arg)))
		case "ldh":
			c.RegWrite(A, uint64(c.get(ins.arg))&0xffff)
		case "ldb":
			c.RegWrite(A, uint64(c.get(ins.arg))&0xff)
		case "ldx":
			fallthrough
		case "ldxi":
			c.RegWrite(X, uint64(c.get(ins.arg)))
		case "ldxb":
			c.RegWrite(X, uint64(c.get(ins.arg))&0xff)
		case "st":
			c.RegWrite(int(c.get(ins.arg)), uint64(a))
		case "stx":
			c.RegWrite(int(c.get(ins.arg)), uint64(x))
		case "jmp":
			jumpoff = c.getJump(ins.arg)
		case "jeq":
			if c.get(ins.arg) == a {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case "jgt":
			if c.get(ins.arg) > a {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case "jge":
			if c.get(ins.arg) >= a {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case "jset":
			if (c.get(ins.arg) & a) != 0 {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case "add":
			c.RegWrite(A, uint64(a+c.get(ins.arg)))
		case "sub":
			c.RegWrite(A, uint64(a-c.get(ins.arg)))
		case "mul":
			c.RegWrite(A, uint64(a*c.get(ins.arg)))
		case "div":
			c.RegWrite(A, uint64(a/c.get(ins.arg)))
		case "mod":
			c.RegWrite(A, uint64(a%c.get(ins.arg)))
		case "neg":
			c.RegWrite(A, uint64(-a))
		case "and":
			c.RegWrite(A, uint64(a&c.get(ins.arg)))
		case "or":
			c.RegWrite(A, uint64(a&c.get(ins.arg)))
		case "xor":
			c.RegWrite(A, uint64(a^c.get(ins.arg)))
		case "lsh":
			c.RegWrite(A, uint64(a<<c.get(ins.arg)))
		case "rsh":
			c.RegWrite(A, uint64(a>>c.get(ins.arg)))
		case "tax":
			c.RegWrite(X, uint64(a))
		case "txa":
			c.RegWrite(A, uint64(x))
		}
		pc += 8 + jumpoff
	}
	return err
}

// TODO: Implement these
func (c *BpfCpu) Stop() error {
	return nil
}

func (c *BpfCpu) Close() error {
	return nil
}

func (c *BpfCpu) Backend() interface{} {
	return nil
}
