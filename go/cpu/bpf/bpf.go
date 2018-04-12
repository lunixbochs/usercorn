package bpf

import (
	"encoding/binary"

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

	returnValue uint32
	exitRequest bool
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
func (c *BpfCpu) getJump(a arg) uint64 {
	switch a := a.(type) {
	case *jabs:
		return uint64(a.val) * 8
	case *j:
		return uint64(a.jf) * 8
	case *jelse:
		return uint64(a.jf) * 8
	default:
		panic("Jump with illegal args!")
	}
}

// getJumpElse gets the jump else case offset in bytes
func (c *BpfCpu) getJumpElse(a arg) uint64 {
	switch a := a.(type) {
	case *j:
		return 0
	case *jelse:
		return uint64(a.jt) * 8
	default:
		panic("Jump with illegal args!")
	}
}

func (c *BpfCpu) Start(begin, until uint64) error {
	var dis Dis
	pc := begin
	c.RegWrite(PC, (pc))
	c.OnBlock(pc, 0)
	var err error

	c.exitRequest = false
	for pc <= until && err == nil && !c.exitRequest {
		var mem []byte
		var code []models.Ins

		if mem, err = c.ReadProt(pc, 8, cpu.PROT_EXEC); err != nil {
			break
		}
		if code, err = dis.Dis(mem, pc); err != nil {
			break
		}
		ins := code[0].(*ins)

		c.OnCode(pc, uint32(len(ins.bytes)))
		if c.exitRequest {
			break
		}

		jumpoff := uint64(0)
		al, _ := c.RegRead(A)
		a := uint32(al)
		xl, _ := c.RegRead(X)
		x := uint32(xl)

		switch ins.optype {
		case CLASS_RET:
			c.exitRequest = true
			c.returnValue = c.get(ins.arg)
			c.OnBlock(pc, 0)
		case CLASS_LD:
			c.RegWrite(A, uint64(c.get(ins.arg))&ins.mask)
		case CLASS_LDX:
			c.RegWrite(X, uint64(c.get(ins.arg))&ins.mask)
		case CLASS_ST:
			c.RegWrite(int(c.get(ins.arg)), uint64(a))
		case CLASS_STX:
			c.RegWrite(int(c.get(ins.arg)), uint64(x))
		case OP_JMP_JA:
			jumpoff = c.getJump(ins.arg)
		case OP_JMP_JEQ:
			if c.get(ins.arg) == a {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case OP_JMP_JGT:
			if c.get(ins.arg) > a {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case OP_JMP_JGE:
			if c.get(ins.arg) >= a {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case OP_JMP_JSET:
			if (c.get(ins.arg) & a) != 0 {
				jumpoff = c.getJump(ins.arg)
			} else {
				jumpoff = c.getJumpElse(ins.arg)
			}
		case OP_ALU_ADD:
			c.RegWrite(A, uint64(a+c.get(ins.arg)))
		case OP_ALU_SUB:
			c.RegWrite(A, uint64(a-c.get(ins.arg)))
		case OP_ALU_MUL:
			c.RegWrite(A, uint64(a*c.get(ins.arg)))
		case OP_ALU_DIV:
			c.RegWrite(A, uint64(a/c.get(ins.arg)))
		case OP_ALU_MOD:
			c.RegWrite(A, uint64(a%c.get(ins.arg)))
		case OP_ALU_NEG:
			c.RegWrite(A, uint64(-a))
		case OP_ALU_AND:
			c.RegWrite(A, uint64(a&c.get(ins.arg)))
		case OP_ALU_OR:
			c.RegWrite(A, uint64(a|c.get(ins.arg)))
		case OP_ALU_XOR:
			c.RegWrite(A, uint64(a^c.get(ins.arg)))
		case OP_ALU_LSH:
			c.RegWrite(A, uint64(a<<c.get(ins.arg)))
		case OP_ALU_RSH:
			c.RegWrite(A, uint64(a>>c.get(ins.arg)))
		case OP_TAX:
			c.RegWrite(X, uint64(a))
		case OP_TXA:
			c.RegWrite(A, uint64(x))
		}

		pc += 8 + jumpoff
		if jumpoff > 0 {
			c.OnBlock(pc, 0)
		}
		c.RegWrite(PC, (pc))
	}
	return err
}

func (c *BpfCpu) Stop() error {
	c.exitRequest = true
	return nil
}

// TODO: Implement these
func (c *BpfCpu) Close() error {
	return nil
}

func (c *BpfCpu) Backend() interface{} {
	return nil
}
