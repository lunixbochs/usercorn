package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/lunixbochs/usercorn/go/models"
)

type ins struct {
	addr  uint64
	op    uint16
	jt    uint8
	jf    uint8
	k     uint32 // Depends on addressing mode?
	name  string
	arg   arg
	bytes []byte

	ptr  uint64
	tipe uint64
}

// Needs to conform to models.Ins
func (i *ins) String() string {
	return i.name + " " + i.OpStr()
}

func (i *ins) Addr() uint64 {
	return i.addr
}

func (i *ins) Bytes() []byte {
	return i.bytes
}

func (i *ins) Mnemonic() string {
	return i.name
}

func (i *ins) OpStr() string {
	return i.arg.String()
}

type arg interface {
	String() string
}

// Define arg types
type regX struct{}
type abs struct{ val uint32 }
type mem struct{ val uint32 }
type ind struct{ val uint32 }
type imm struct{ val uint32 }
type msh struct{ val uint32 }
type jabs struct{ val uint32 }
type j struct {
	val uint32
	jf  uint8
}
type jelse struct {
	val    uint32
	jf, jt uint8
}
type regA struct{}
type misc struct{ name string }

func (a *regX) String() string  { return "X" }
func (a *abs) String() string   { return fmt.Sprintf("[%d]", a.val) }
func (a *mem) String() string   { return fmt.Sprintf("M[%d]", a.val) }
func (a *ind) String() string   { return fmt.Sprintf("[x + %d]", a.val) }
func (a *imm) String() string   { return fmt.Sprintf("#%#x", a.val) }
func (a *msh) String() string   { return fmt.Sprintf("4*([%#x]&0xf)", a.val) }
func (a *jabs) String() string  { return fmt.Sprintf("+%d", a.val) }
func (a *j) String() string     { return fmt.Sprintf("#%#x,%d", a.val, a.jf) }
func (a *jelse) String() string { return fmt.Sprintf("#%#x,%d,%d", a.val, a.jf, a.jt) }
func (a *regA) String() string  { return "A" }
func (a *misc) String() string  { return a.name }

type insReader struct {
	*bytes.Reader
	err  error
	addr uint64
}

const UT64_MAX = 0xffffffffffffffff

func (ir *insReader) tell() int64 {
	return ir.Size() - int64(ir.Len())
}

// ins reads out exactly one instruction
func (ir *insReader) ins() models.Ins {
	i := &ins{}
	i.bytes = make([]byte, 8)
	i.addr = ir.addr + uint64(ir.tell())
	_, err := ir.Read(i.bytes)
	if err != nil {
		return nil
	}
	i.op = binary.LittleEndian.Uint16(i.bytes)
	i.jt = i.bytes[2]
	i.jf = i.bytes[3]
	i.k = binary.LittleEndian.Uint32(i.bytes[4:])

	if op, ok := opCodes[i.op]; ok {
		var arg arg
		switch op.arg {
		case A_X:
			arg = &regX{}
		case A_ABS:
			arg = &abs{i.k}
		case A_MEM:
			arg = &mem{i.k}
		case A_IND:
			arg = &ind{i.k}
		case A_IMM:
			arg = &imm{i.k}
		case A_MSH:
			arg = &msh{i.k}
		case A_JABS:
			arg = &jabs{i.k}
		case A_JELSE:
			arg = &jelse{i.k, i.jt, i.jf}
		case A_J:
			arg = &j{i.k, i.jt}
		case A_A:
			arg = &regA{}
		case A_LEN:
			arg = nil // TODO
		case A_NONE:
			arg = &misc{""}
		}
		i.name = op.name
		i.arg = arg
		return i
	} else {
		// TODO: Remove this once we have all legal opcodes
		fmt.Printf("opcode %#x not found in table\n", i.op)
	}
	return nil
}

type Dis struct{}

func (d *Dis) Dis(mem []byte, addr uint64) ([]models.Ins, error) {
	reader := &insReader{
		addr:   addr,
		Reader: bytes.NewReader(mem),
	}
	var ret []models.Ins
	for {
		ins := reader.ins()
		if ins == nil || reader.err != nil {
			break
		}
		ret = append(ret, ins)
	}
	return ret, nil
}