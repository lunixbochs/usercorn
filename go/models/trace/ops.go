package trace

import (
	"encoding/binary"
	"github.com/pkg/errors"
	"io"

	"github.com/lunixbochs/usercorn/go/models"
)

var order = binary.LittleEndian

const (
	OP_NOP       = 0
	OP_FRAME     = 1
	OP_KEYFRAME  = 2
	OP_JMP       = 3
	OP_STEP      = 4
	OP_REG       = 5
	OP_SPREG     = 6
	OP_MEM_READ  = 7
	OP_MEM_WRITE = 8
	OP_MEM_MAP   = 9
	OP_MEM_UNMAP = 10
	OP_MEM_PROT  = 11
	OP_SYSCALL   = 12
	OP_EXIT      = 13
)

// used by frame, keyframe, and syscall
func packOps(p []byte, ops []models.Op) {
	for _, op := range ops {
		op.Pack(p)
		p = p[op.Sizeof():]
	}
}

// used by frame, keyframe, and syscall
func unpackOps(r io.Reader, count int) (ops []models.Op, total int, err error) {
	ops = make([]models.Op, count)
	for i := 0; i < count; i++ {
		op, n, err := Unpack(r, true)
		if err != nil {
			return ops, total + n, errors.Wrap(err, "unpacking op list")
		} else {
			total += n
		}
		ops[i] = op
	}
	return ops, total, nil
}

func Unpack(r io.Reader, nested bool) (models.Op, int, error) {
	var tmp [1]byte
	if _, err := r.Read(tmp[:]); err != nil {
		return nil, 0, err
	}
	var op models.Op
	switch tmp[0] {
	case OP_NOP:
		op = &OpNop{}
	case OP_JMP:
		op = &OpJmp{}
	case OP_STEP:
		op = &OpStep{}
	case OP_REG:
		op = &OpReg{}
	case OP_SPREG:
		op = &OpSpReg{}
	case OP_MEM_READ:
		op = &OpMemRead{}
	case OP_MEM_WRITE:
		op = &OpMemWrite{}
	case OP_MEM_MAP:
		op = &OpMemMap{}
	case OP_MEM_UNMAP:
		op = &OpMemUnmap{}
	case OP_MEM_PROT:
		op = &OpMemProt{}
	case OP_SYSCALL:
		op = &OpSyscall{}
	case OP_FRAME:
		op = &OpFrame{}
	case OP_KEYFRAME:
		op = &OpKeyframe{}
	case OP_EXIT:
		op = &OpExit{}
	default:
		return nil, 0, errors.Errorf("Unknown op: %d", tmp[0])
	}
	if nested && (tmp[0] == OP_FRAME || tmp[0] == OP_KEYFRAME) {
		return nil, 0, errors.Errorf("fatal: nested frame")
	}
	n, err := op.Unpack(r)
	return op, n + 1, err
}

type OpNop struct{}

func (o *OpNop) Sizeof() int   { return 1 }
func (o *OpNop) Pack(p []byte) { p[0] = OP_NOP }

func (o *OpNop) Unpack(r io.Reader) (int, error) { return 0, nil }

type OpExit struct{ OpNop }

func (o *OpExit) Pack(p []byte) { p[0] = OP_EXIT }

type OpJmp struct {
	Addr uint64
	Size uint32
}

func (o *OpJmp) Sizeof() int { return 1 + 8 + 4 }
func (o *OpJmp) Pack(p []byte) {
	p[0] = OP_JMP
	order.PutUint64(p[1:], o.Addr)
	order.PutUint32(p[9:], o.Size)
}

func (o *OpJmp) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 4]byte
	n, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint32(tmp[8:])
	}
	return n, err
}

type OpStep struct {
	Size uint8
}

func (o *OpStep) Sizeof() int { return 2 }
func (o *OpStep) Pack(p []byte) {
	p[0] = OP_STEP
	p[1] = o.Size
}

func (o *OpStep) Unpack(r io.Reader) (int, error) {
	var tmp [1]byte
	n, err := r.Read(tmp[:])
	if err == nil {
		o.Size = uint8(tmp[0])
	}
	return n, err
}

type OpReg struct {
	Num uint16
	Val uint64
}

func (o *OpReg) Sizeof() int { return 1 + 2 + 8 }
func (o *OpReg) Pack(p []byte) {
	p[0] = OP_REG
	order.PutUint16(p[1:], o.Num)
	order.PutUint64(p[3:], o.Val)
}

func (o *OpReg) Unpack(r io.Reader) (int, error) {
	var tmp [2 + 8]byte
	n, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Num = order.Uint16(tmp[:])
		o.Val = order.Uint64(tmp[2:])
	}
	return n, err
}

type OpSpReg struct {
	Num uint16
	Val []byte
}

func (o *OpSpReg) Sizeof() int { return 1 + 2 + 2 + len(o.Val) }
func (o *OpSpReg) Pack(p []byte) {
	p[0] = OP_SPREG
	order.PutUint16(p[1:], o.Num)
	order.PutUint16(p[3:], uint16(len(o.Val)))
	copy(p[5:], o.Val)
}

func (o *OpSpReg) Unpack(r io.Reader) (int, error) {
	var tmp [2 + 2]byte
	total, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Num = order.Uint16(tmp[:])
		size := order.Uint16(tmp[2:])
		o.Val = make([]byte, size)
		n, err := io.ReadFull(r, o.Val)
		return total + n, err
	}
	return total, err
}

type OpMemRead struct {
	Addr uint64
	Size uint32
}

func (o *OpMemRead) Sizeof() int { return 1 + 8 + 4 }
func (o *OpMemRead) Pack(p []byte) {
	p[0] = OP_MEM_READ
	order.PutUint64(p[1:], o.Addr)
	order.PutUint32(p[9:], o.Size)
}

func (o *OpMemRead) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 4]byte
	total, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint32(tmp[8:])
	}
	return total, err
}

type OpMemWrite struct {
	Addr uint64
	Data []byte
}

func (o *OpMemWrite) Sizeof() int { return 1 + 8 + 4 + len(o.Data) }
func (o *OpMemWrite) Pack(p []byte) {
	p[0] = OP_MEM_WRITE
	order.PutUint64(p[1:], o.Addr)
	order.PutUint32(p[9:], uint32(len(o.Data)))
	copy(p[13:], o.Data)
}

func (o *OpMemWrite) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 4]byte
	total, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		size := order.Uint32(tmp[8:])
		o.Data = make([]byte, size)
		if n, err := io.ReadFull(r, o.Data); err != nil {
			return total + n, err
		} else {
			total += n
		}
	}
	return total, err
}

type OpMemMap struct {
	Addr uint64
	Size uint64
	Prot uint8

	Off  uint64
	Len  uint64
	Desc string
	File string
}

func (o *OpMemMap) Sizeof() int {
	return 1 + 8 + 8 + 1 + 8 + 8 + 2 + 2 + len([]byte(o.Desc)) + len([]byte(o.File))
}
func (o *OpMemMap) Pack(p []byte) {
	desc, file := []byte(o.Desc), []byte(o.File)
	// op, addr, size, prot(1), off, len, dlen, flen
	p[0] = OP_MEM_MAP
	order.PutUint64(p[1:], o.Addr)
	order.PutUint64(p[9:], o.Size)
	p[17] = o.Prot
	order.PutUint64(p[18:], o.Off)
	order.PutUint64(p[26:], o.Len)
	order.PutUint16(p[34:], uint16(len(desc)))
	order.PutUint16(p[36:], uint16(len(file)))
	copy(p[38:], desc)
	copy(p[38+len(desc):], file)
}

func (o *OpMemMap) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 8 + 1 + 8 + 8 + 2 + 2]byte
	total, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint64(tmp[8:])
		o.Prot = tmp[16]
		o.Off = order.Uint64(tmp[17:])
		o.Len = order.Uint64(tmp[25:])
		dlen := order.Uint16(tmp[33:])
		flen := order.Uint16(tmp[35:])
		buf := make([]byte, dlen+flen)

		n, err := io.ReadFull(r, buf)
		total += n
		if err != nil {
			return total, err
		}
		o.Desc = string(buf[:dlen])
		o.File = string(buf[dlen:])
	}
	return total, err
}

type OpMemUnmap struct {
	Addr uint64
	Size uint64
}

func (o *OpMemUnmap) Sizeof() int { return 1 + 8 + 8 }
func (o *OpMemUnmap) Pack(p []byte) {
	p[0] = OP_MEM_UNMAP
	order.PutUint64(p[1:], o.Addr)
	order.PutUint64(p[9:], o.Size)
}

func (o *OpMemUnmap) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 8]byte
	n, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint64(tmp[8:])
	}
	return n, err
}

type OpMemProt struct {
	Addr uint64
	Size uint64
	Prot uint8
}

func (o *OpMemProt) Sizeof() int { return 1 + 8 + 8 + 1 }
func (o *OpMemProt) Pack(p []byte) {
	p[0] = OP_MEM_PROT
	order.PutUint64(p[1:], o.Addr)
	order.PutUint64(p[9:], o.Size)
	p[17] = o.Prot
}

func (o *OpMemProt) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 8 + 1]byte
	n, err := io.ReadFull(r, tmp[:])
	if err == nil {
		o.Addr = order.Uint64(tmp[:])
		o.Size = order.Uint64(tmp[8:])
		o.Prot = tmp[16]
	}
	return n, err
}

type OpSyscall struct {
	Num  uint32
	Ret  uint64
	Args []uint64
	Desc string
	Ops  []models.Op
}

func (o *OpSyscall) Sizeof() int {
	size := 1 + 4 + 8 + 1 + 2 + len(o.Args)*8
	for _, op := range o.Ops {
		size += op.Sizeof()
	}
	return size
}
func (o *OpSyscall) Pack(p []byte) {
	// pack header
	size := 1 + 4 + 8 + 1 + 2
	p[0] = OP_SYSCALL
	order.PutUint32(p[1:], o.Num)
	order.PutUint64(p[5:], o.Ret)
	p[13] = uint8(len(o.Args))
	order.PutUint16(p[14:], uint16(len(o.Ops)))
	// pack args
	for i, v := range o.Args {
		order.PutUint64(p[size+i*8:], v)
	}
	packOps(p[size+len(o.Args)*8:], o.Ops)
}

func (o *OpSyscall) Unpack(r io.Reader) (int, error) {
	var tmp [4 + 8 + 2 + 1]byte
	total, err := io.ReadFull(r, tmp[:])
	if err == nil {
		// unpack header
		o.Num = order.Uint32(tmp[:])
		o.Ret = order.Uint64(tmp[4:])
		args := int(tmp[12])
		count := int(order.Uint16(tmp[13:]))

		// unpack args
		tmp2 := make([]byte, 8*args)
		n, err := io.ReadFull(r, tmp2[:])
		if err != nil {
			return total + n, errors.Wrap(err, "syscall unpack")
		} else {
			total += n
		}
		o.Args = make([]uint64, args)
		for i := 0; i < args; i++ {
			o.Args[i] = order.Uint64(tmp2[i*8:])
		}

		// unpack sub-ops
		o.Ops, n, err = unpackOps(r, count)
		total += n
	}
	return total, errors.Wrap(err, "syscall unpack")
}

type OpKeyframe struct {
	Pid uint64
	Ops []models.Op
}

func (o *OpKeyframe) Sizeof() int {
	size := 1 + 8 + 4
	for _, op := range o.Ops {
		size += op.Sizeof()
	}
	return size
}
func (o *OpKeyframe) Pack(p []byte) {
	p[0] = OP_KEYFRAME
	order.PutUint64(p[1:], o.Pid)
	order.PutUint32(p[9:], uint32(len(o.Ops)))
	packOps(p[1+8+4:], o.Ops)
}

func (o *OpKeyframe) Unpack(r io.Reader) (int, error) {
	return (*OpFrame)(o).Unpack(r)
}

type OpFrame struct {
	Pid uint64
	Ops []models.Op
}

func (o *OpFrame) Sizeof() int {
	size := 1 + 8 + 4
	for _, op := range o.Ops {
		size += op.Sizeof()
	}
	return size
}
func (o *OpFrame) Pack(p []byte) {
	p[0] = OP_FRAME
	order.PutUint64(p[1:], o.Pid)
	order.PutUint32(p[9:], uint32(len(o.Ops)))
	packOps(p[1+8+4:], o.Ops)
}

func (o *OpFrame) Unpack(r io.Reader) (int, error) {
	var tmp [8 + 4]byte
	total, err := io.ReadFull(r, tmp[:])
	if err != nil {
		return total, errors.Wrap(err, "frame unpack")
	} else {
		o.Pid = order.Uint64(tmp[:])
		count := int(order.Uint32(tmp[8:]))
		// unpack sub-ops
		ops, n, err := unpackOps(r, count)
		o.Ops = ops
		return total + n, err
	}
}
