package ndh

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

func rbool(i bool) uint64 {
	if i {
		return 1
	}
	return 0
}

type Builder struct{}

func (b *Builder) New() (cpu.Cpu, error) {
	c := &NdhCpu{
		Regs: cpu.NewRegs(16, []int{
			R0, R1, R2, R3, R4, R5, R6, R7,
			BP, SP, PC,
			ZF, AF, BF,
		}),
		Mem: cpu.NewMem(16, binary.LittleEndian),
	}
	c.Hooks = cpu.NewHooks(c, c.Mem)
	return c, nil
}

type NdhCpu struct {
	*cpu.Hooks
	*cpu.Regs
	*cpu.Mem

	exitRequest bool
	err         error
}

func (n *NdhCpu) set(a arg, val uint64) {
	switch v := a.(type) {
	case *reg:
		n.RegWrite(int(v.num), val)
	case *indirect:
		addr := n.get(v.arg.(*reg))
		n.WriteUint(addr, 1, cpu.PROT_WRITE, val)
	default:
		panic(fmt.Sprintf("unsupported set: %T", a))
	}
}

func (n *NdhCpu) get(a arg) uint64 {
	var val uint64
	switch v := a.(type) {
	case *u8:
		val = uint64(v.val)
	case *u16:
		val = uint64(v.val)
	case *reg:
		val, _ = n.RegRead(int(v.num))
	case *indirect:
		addr := n.get(v.arg.(*reg))
		val, n.err = n.ReadUint(addr, 1, cpu.PROT_READ)
	default:
		panic(fmt.Sprintf("unsupported get: %T", a))
	}
	return val
}

func (n *NdhCpu) Start(begin, until uint64) error {
	var dis Dis
	var err error
	n.exitRequest = false
	pc := begin
	n.RegWrite(PC, pc)
	n.OnBlock(pc, 0)

	for pc != until && err == nil && !n.exitRequest {
		var mem []byte
		var code []models.Ins
		// 5 is the largest known ndh instruction size
		if mem, err = n.ReadProt(pc, 5, cpu.PROT_EXEC); err != nil {
			break
		}
		if code, err = dis.Dis(mem, pc); err != nil {
			break
		}
		if len(code) < 1 {
			panic("eof")
		}
		ins := code[0].(*ins)

		n.OnCode(pc, uint32(len(ins.bytes)))
		// exitRequest needs to be checked here so a hook can interrupt the emulator
		if n.exitRequest {
			break
		}
		// TODO: allow OnCode and OnBlock to set PC?

		var a, b arg
		switch len(ins.args) {
		case 2:
			a = ins.args[0]
			b = ins.args[1]
		case 1:
			a = ins.args[0]
		}

		next_pc := pc + uint64(len(ins.Bytes()))
		jmpoff := int32(-1)
		afr, _ := n.RegRead(AF)
		bfr, _ := n.RegRead(BF)
		zfr, _ := n.RegRead(ZF)
		sp, _ := n.RegRead(SP)
		af, bf, zf := afr == 1, bfr == 1, zfr == 1

		zfcheck := func(val uint64) uint64 {
			zf = val == 0
			return val
		}

		switch ins.op {
		case OP_DEC:
			n.set(a, n.get(a)-1)
		case OP_INC:
			n.set(a, n.get(a)+1)
		case OP_XCHG:
			xa, xb := n.get(a), n.get(b)
			n.set(a, xb)
			n.set(b, xa)
		case OP_MOV:
			n.set(a, n.get(b))

		case OP_ADD:
			n.set(a, zfcheck(n.get(a)+n.get(b)))
		case OP_AND:
			n.set(a, zfcheck(n.get(a)&n.get(b)))
		case OP_DIV:
			n.set(a, zfcheck(n.get(a)/n.get(b)))
		case OP_MUL:
			n.set(a, zfcheck(n.get(a)*n.get(b)))
		case OP_NOT:
			n.set(a, zfcheck(^n.get(a)))
		case OP_OR:
			n.set(a, zfcheck(n.get(a)|n.get(b)))
		case OP_SUB:
			n.set(a, zfcheck(n.get(a)-n.get(b)))
		case OP_XOR:
			n.set(a, zfcheck(n.get(a)^n.get(b)))

		case OP_CMP:
			va, vb := n.get(a), n.get(b)
			af, bf, zf = false, false, false
			if va == vb {
				zf = true
			} else if va < vb {
				af = true
			} else if va > vb {
				bf = true
			}
		case OP_TEST:
			zf = n.get(a) == 0 && n.get(b) == 0

		case OP_SYSCALL:
			n.OnIntr(0)
		case OP_NOP:
		case OP_END:
			return models.ExitStatus(0)
		case OP_JA:
			if af {
				jmpoff = int32(n.get(a))
			}
		case OP_JB:
			if bf {
				jmpoff = int32(n.get(a))
			}
		case OP_JMPL, OP_JMPS:
			jmpoff = int32(n.get(a))
		case OP_JNZ:
			if !zf {
				jmpoff = int32(n.get(a))
			}
		case OP_JZ:
			if zf {
				jmpoff = int32(n.get(a))
			}

		case OP_CALL:
			jmpoff = int32(n.get(a))
			sp -= 2
			n.err = n.WriteUint(sp, 2, cpu.PROT_WRITE, next_pc)
		case OP_RET:
			next_pc, n.err = n.ReadUint(sp, 2, cpu.PROT_READ)
			n.OnBlock(next_pc, 0)
			sp += 2

		case OP_PUSH:
			size := 2
			if _, ok := a.(*u8); ok {
				size = 1
			}
			sp -= uint64(size)
			val := n.get(a)
			n.err = n.WriteUint(sp, size, cpu.PROT_WRITE, val)
		case OP_POP:
			var val uint64
			val, n.err = n.ReadUint(sp, 2, cpu.PROT_READ)
			n.set(a, val)
			sp += 2

		default:
			return errors.Errorf("invalid op: %#x", ins.op)
		}
		n.RegWrite(AF, rbool(af))
		n.RegWrite(BF, rbool(bf))
		n.RegWrite(ZF, rbool(zf))
		n.RegWrite(SP, sp)

		if jmpoff >= 0 {
			insend := ins.addr + uint64(len(ins.bytes))
			pc = (insend + uint64(jmpoff)) & 0xffff
			jmpoff = 0
			n.OnBlock(pc, 0)
		} else {
			pc = next_pc
		}
		n.RegWrite(PC, pc)
	}
	return n.err
}

func (n *NdhCpu) Stop() error {
	n.exitRequest = true
	return nil
}

func (n *NdhCpu) Close() error {
	return nil
}

func (n *NdhCpu) Backend() interface{} {
	return n
}
