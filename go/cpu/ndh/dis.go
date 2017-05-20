package ndh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

type ins struct {
	addr  uint64
	op    byte
	name  string
	args  []arg
	bytes []byte
}

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
	var args []string
	for _, a := range i.args {
		args = append(args, a.String())
	}
	return strings.Join(args, ", ")
}

type arg interface {
	String() string
}

type u8 struct{ val uint8 }
type u16 struct{ val uint16 }
type reg struct{ num uint8 }
type indirect struct{ arg arg }

func (a *u8) String() string  { return fmt.Sprintf("%#x", a.val) }
func (a *u16) String() string { return fmt.Sprintf("%#x", a.val) }
func (a *reg) String() string {
	switch a.num {
	case PC:
		return "pc"
	case SP:
		return "sp"
	case BP:
		return "bp"
	default:
		return fmt.Sprintf("r%d", a.num)
	}
}

func (a *indirect) String() string { return "[" + a.arg.String() + "]" }

type insReader struct {
	*bytes.Reader
	err  error
	addr uint64
}

func (i *insReader) r8() uint8 {
	b, err := i.ReadByte()
	i.err = err
	return b
}

func (i *insReader) r16() uint16 {
	var tmp [2]byte
	_, i.err = i.Read(tmp[:])
	return binary.LittleEndian.Uint16(tmp[:])
}

func (i *insReader) u8() arg {
	return &u8{i.r8()}
}

func (i *insReader) u16() arg {
	return &u16{i.r16()}
}

func (i *insReader) reg() arg {
	return &reg{i.r8()}
}

func (i *insReader) flag() []arg {
	flag := i.r8()
	var args []arg
	switch flag {
	case OP_FLAG_REG_REG:
		args = []arg{i.reg(), i.reg()}

	case OP_FLAG_REG_DIRECT08:
		args = []arg{i.reg(), i.u8()}

	case OP_FLAG_REG_DIRECT16:
		args = []arg{i.reg(), i.u16()}

	case OP_FLAG_REG:
		args = []arg{i.reg()}

	case OP_FLAG_DIRECT16:
		args = []arg{i.u16()}

	case OP_FLAG_DIRECT08:
		args = []arg{i.u8()}

	case OP_FLAG_REGINDIRECT_REG:
		args = []arg{&indirect{i.reg()}}

	case OP_FLAG_REGINDIRECT_DIRECT08:
		args = []arg{&indirect{i.reg()}, i.u8()}

	case OP_FLAG_REGINDIRECT_DIRECT16:
		args = []arg{&indirect{i.reg()}, i.u16()}

	case OP_FLAG_REGINDIRECT_REGINDIRECT:
		args = []arg{&indirect{i.reg()}, &indirect{i.reg()}}

	case OP_FLAG_REG_REGINDIRECT:
		args = []arg{i.reg(), &indirect{i.reg()}}
	}
	return args
}

func (i *insReader) tell() int64 {
	return i.Size() - int64(i.Len())
}

func (i *insReader) ins() models.Ins {
	start := i.tell()
	b, err := i.ReadByte()
	if err != nil {
		return nil
	}
	if data, ok := opData[int(b)]; ok {
		var args []arg
		switch data.arg {
		case A_NONE:
		case A_1REG:
			args = []arg{i.reg()}
		case A_2REG:
			args = []arg{i.reg(), i.reg()}
		case A_U8:
			args = []arg{i.u8()}
		case A_U16:
			args = []arg{i.u16()}
		case A_FLAG:
			args = i.flag()
		}
		p := make([]byte, i.tell()-start)
		i.ReadAt(p, start)
		return &ins{
			addr:  i.addr + uint64(start),
			op:    b,
			name:  data.name,
			args:  args,
			bytes: p,
		}
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
