package record

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
)

var order = binary.BigEndian

const (
	OP_NOP = iota
	OP_FRAME

	OP_EXEC_ABS
	OP_EXEC_REL

	OP_REG_CHANGE
	OP_SPREG_CHANGE

	OP_MEM_READ
	OP_MEM_WRITE
	OP_MEM_MAP
	OP_MEM_UNMAP

	OP_SYSCALL
	OP_EXIT
)

type Op interface {
	Pack(w io.Writer) (int, error)
	Unpack(r io.Reader) (int, error)
}

func Pack(w io.Writer, op Op) (int, error) {
	var tmp [1]byte
	var e byte
	switch op.(type) {
	case *OpNop:
		e = OP_NOP
	case *OpExecAbs:
		e = OP_EXEC_ABS
	case *OpExecRel:
		e = OP_EXEC_REL
	case *OpRegChange:
		e = OP_REG_CHANGE
	case *OpSpRegChange:
		e = OP_SPREG_CHANGE
	case *OpMemRead:
		e = OP_MEM_READ
	case *OpMemWrite:
		e = OP_MEM_WRITE
	case *OpMemMap:
		e = OP_MEM_MAP
	case *OpMemUnmap:
		e = OP_MEM_UNMAP
	case *OpSyscall:
		e = OP_SYSCALL
	case *OpFrame:
		e = OP_FRAME
	case *OpExit:
		e = OP_EXIT
	default:
		return 0, fmt.Errorf("Unknown OP type: %T", op)
	}
	tmp[0] = e

	total, err := w.Write(tmp[:])
	if err != nil {
		return total, err
	}
	return op.Pack(w)
}

func Unpack(r io.Reader) (Op, int, error) {
	var tmp [1]byte
	if _, err := r.Read(tmp[:]); err != nil {
		return nil, 0, err
	}
	var op Op
	switch tmp[0] {
	case OP_NOP:
		op = &OpNop{}
	case OP_EXEC_ABS:
		op = &OpExecAbs{}
	case OP_EXEC_REL:
		op = &OpExecRel{}
	case OP_REG_CHANGE:
		op = &OpRegChange{}
	case OP_SPREG_CHANGE:
		op = &OpSpRegChange{}
	case OP_MEM_READ:
		op = &OpMemRead{}
	case OP_MEM_WRITE:
		op = &OpMemWrite{}
	case OP_MEM_MAP:
		op = &OpMemMap{}
	case OP_MEM_UNMAP:
		op = &OpMemUnmap{}
	case OP_SYSCALL:
		op = &OpSyscall{}
	case OP_FRAME:
		op = &OpFrame{}
	case OP_EXIT:
		op = &OpExit{}
	default:
		return nil, 0, fmt.Errorf("Unknown op: %d", tmp[0])
	}
	n, err := op.Unpack(r)
	return op, n + 1, err
}

type OpNop struct{}

func (o *OpNop) Pack(w io.Writer) (int, error)   { return 0, nil }
func (o *OpNop) Unpack(r io.Reader) (int, error) { return 0, nil }

type OpExit struct{ OpNop }

type OpExecAbs struct {
	Addr uint64
	Size uint16
}

func (o *OpExecAbs) Pack(w io.Writer) (int, error) {
	var tmp [8 + 2]byte
	order.PutUint64(tmp[:], o.Addr)
	order.PutUint16(tmp[8:], o.Size)
	return w.Write(tmp[:])
}

func (o *OpExecAbs) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 2]byte
	n, err := r.Read(tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint16(tmp[8:])
	}
	return n, err
}

type OpExecRel struct {
	Size uint16
}

func (o *OpExecRel) Pack(w io.Writer) (int, error) {
	var tmp [2]byte
	order.PutUint16(tmp[:], o.Size)
	return w.Write(tmp[:])
}

func (o *OpExecRel) Unpack(r io.Reader) (int, error) {
	var tmp [2]byte
	n, err := r.Read(tmp[:])
	if err == nil {
		o.Size = order.Uint16(tmp[:])
	}
	return n, err
}

type OpRegChange struct {
	Enum  uint16
	Value uint64
}

func (o *OpRegChange) Pack(w io.Writer) (int, error) {
	var tmp [2 + 8]byte
	order.PutUint16(tmp[:], o.Enum)
	order.PutUint64(tmp[2:], o.Value)
	return w.Write(tmp[:])
}

func (o *OpRegChange) Unpack(r io.Reader) (int, error) {
	var tmp [2 + 8]byte
	n, err := r.Read(tmp[:])
	if err == nil {
		o.Enum = order.Uint16(tmp[:])
		o.Value = order.Uint64(tmp[2:])
	}
	return n, err
}

type OpSpRegChange struct {
	Enum  uint16
	Value []byte
}

func (o *OpSpRegChange) Pack(w io.Writer) (int, error) {
	var tmp [2 + 2]byte
	order.PutUint16(tmp[:], o.Enum)
	order.PutUint16(tmp[2:], uint16(len(o.Value)))
	total, err := w.Write(tmp[:])
	if err != nil {
		return total, err
	}
	n, err := w.Write(o.Value)
	return total + n, err
}

func (o *OpSpRegChange) Unpack(r io.Reader) (int, error) {
	var tmp [2 + 2]byte
	total, err := r.Read(tmp[:])
	if err == nil {
		o.Enum = order.Uint16(tmp[:])
		size := order.Uint16(tmp[2:])
		o.Value = make([]byte, size)
		n, err := r.Read(o.Value)
		return total + n, err
	}
	return total, err
}

type OpMemRead struct {
	Addr uint64
	Data []byte
}

func (o *OpMemRead) Pack(w io.Writer) (int, error) {
	var tmp [8 + 8]byte
	order.PutUint64(tmp[:], o.Addr)
	order.PutUint64(tmp[8:], uint64(len(o.Data)))
	total, err := w.Write(tmp[:])
	if err != nil {
		return total, err
	}
	n, err := w.Write(o.Data)
	return total + n, err
}

func (o *OpMemRead) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 8]byte
	total, err := r.Read(tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		size := order.Uint64(tmp[8:])
		o.Data = make([]byte, size)
		if n, err := r.Read(o.Data); err != nil {
			return total + n, err
		} else {
			total += n
		}
	}
	return total, err
}

type OpMemWrite struct {
	Addr uint64
	Data []byte
}

func (o *OpMemWrite) Pack(w io.Writer) (int, error) {
	return (*OpMemRead)(o).Pack(w)
}

func (o *OpMemWrite) Unpack(r io.Reader) (int, error) {
	return (*OpMemRead)(o).Unpack(r)
}

type OpMemMap struct {
	Addr uint64
	Size uint64
	Prot uint8
}

func (o *OpMemMap) Pack(w io.Writer) (int, error) {
	var tmp [8 + 8 + 1]byte
	order.PutUint64(tmp[:], o.Addr)
	order.PutUint64(tmp[8:], o.Size)
	tmp[16] = o.Prot
	return w.Write(tmp[:])
}

func (o *OpMemMap) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 8 + 1]byte
	n, err := r.Read(tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint64(tmp[8:])
		o.Prot = tmp[16]
	}
	return n, err
}

type OpMemUnmap struct {
	Addr uint64
	Size uint64
}

func (o *OpMemUnmap) Pack(w io.Writer) (int, error) {
	var tmp [8 + 8]byte
	order.PutUint64(tmp[:], o.Addr)
	order.PutUint64(tmp[8:], o.Size)
	return w.Write(tmp[:])
}

func (o *OpMemUnmap) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 8]byte
	n, err := r.Read(tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint64(tmp[8:])
	}
	return n, err
}

type OpSyscall struct {
	Index uint32
	Ret   uint64
	Args  []uint64
	Ops   []Op
}

func (o *OpSyscall) Pack(w io.Writer) (int, error) {
	total := 0

	// pack header
	var tmp [4 + 8 + 2 + 2]byte
	order.PutUint32(tmp[:], o.Index)
	order.PutUint64(tmp[4:], o.Ret)
	order.PutUint16(tmp[12:], uint16(len(o.Args)))
	order.PutUint16(tmp[14:], uint16(len(o.Ops)))
	if n, err := w.Write(tmp[:]); err != nil {
		return total + n, err
	} else {
		total += n
	}

	// pack args
	tmp2 := make([]byte, len(o.Args)*8)
	for i, v := range o.Args {
		order.PutUint64(tmp2[i*8:], v)
	}
	if n, err := w.Write(tmp2); err != nil {
		return total + n, err
	} else {
		total += n
	}

	// pack sub-ops
	for _, v := range o.Ops {
		if n, err := v.Pack(w); err != nil {
			return total + n, err
		} else {
			total += n
		}
	}
	return total, nil
}

func (o *OpSyscall) Unpack(r io.Reader) (int, error) {
	var tmp [4 + 8 + 2 + 2]byte
	total, err := r.Read(tmp[:])
	if err == nil {
		// unpack header
		o.Index = order.Uint32(tmp[:])
		o.Ret = order.Uint64(tmp[4:])
		args := int(order.Uint16(tmp[12:]))
		ops := int(order.Uint16(tmp[14:]))

		// unpack args
		tmp2 := make([]byte, 8*args)
		if n, err := r.Read(tmp2[:]); err != nil {
			return total + n, err
		} else {
			total += n
		}
		o.Args = make([]uint64, args)
		for i := 0; i < args; i++ {
			o.Args[i] = order.Uint64(tmp2[i*8:])
		}

		// unpack subops
		o.Ops = make([]Op, ops)
		for i := 0; i < ops; i++ {
			op, n, err := Unpack(r)
			if err != nil {
				return total + n, err
			} else {
				total += n
			}
			o.Ops[i] = op
		}
	}
	return total, err
}

type OpFrame struct {
	Keyframe bool
	Ops      []Op
}

func (o *OpFrame) Pack(w io.Writer) (int, error) {
	// compress internal ops
	var compressed bytes.Buffer
	z := zlib.NewWriter(&compressed)
	for _, v := range o.Ops {
		if _, err := v.Pack(z); err != nil {
			return 0, err
		}
	}
	z.Close()

	// pack header
	var tmp [1 + 4 + 4]byte
	if o.Keyframe {
		tmp[0] = 0
	} else {
		tmp[0] = 1
	}
	order.PutUint32(tmp[1:], uint32(len(o.Ops)))
	order.PutUint32(tmp[5:], uint32(compressed.Len()))
	total, err := w.Write(tmp[:])
	if err != nil {
		return total, err
	}

	// write compressed data
	n, err := compressed.WriteTo(w)
	return total + int(n), err
}

func (o *OpFrame) Unpack(r io.Reader) (int, error) {
	var tmp [1 + 4 + 4]byte
	total, err := r.Read(tmp[:])
	if err == nil {
		o.Keyframe = !(tmp[0] == 0)
		ops := int(order.Uint32(tmp[1:]))
		compLen := order.Uint32(tmp[5:])

		z, err := zlib.NewReader(&io.LimitedReader{r, int64(compLen)})
		if err != nil {
			return 0, err
		}

		// unpack sub-ops
		o.Ops = make([]Op, ops)
		for i := 0; i < ops; i++ {
			op, n, err := Unpack(z)
			if err != nil {
				return total + n, err
			} else {
				total += n
			}
			o.Ops[i] = op
		}
	}
	return total, err
}
