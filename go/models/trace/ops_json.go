package trace

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/lunixbochs/usercorn/go/models"
)

type msp map[string]interface{}

func marshalOps(ops []models.Op) []byte {
	bops := make([][]byte, len(ops))
	for i, op := range ops {
		bops[i], _ = op.MarshalJSON()
	}
	return bytes.Join(bops, []byte(","))
}

func (o *OpNop) MarshalJSON() ([]byte, error) {
	return append(strconv.AppendUint([]byte(`{"op":`), OP_NOP, 10), '}'), nil
}

func (o *OpExit) MarshalJSON() ([]byte, error) {
	return append(strconv.AppendUint([]byte(`{"op":`), OP_EXIT, 10), '}'), nil
}

func (o *OpJmp) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_JMP, 10), []byte(`,"addr":`)...)
	out = append(strconv.AppendUint(out, o.Addr, 10), []byte(`,"size":`)...)
	return append(strconv.AppendUint(out, uint64(o.Size), 10), '}'), nil
}

func (o *OpStep) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_STEP, 10), []byte(`,"size":`)...)
	return append(strconv.AppendUint(out, uint64(o.Size), 10), '}'), nil
}

func (o *OpReg) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_REG, 10), []byte(`,"num":`)...)
	out = append(strconv.AppendUint(out, uint64(o.Num), 10), []byte(`,"val":`)...)
	return append(strconv.AppendUint(out, uint64(o.Val), 10), '}'), nil
}

func (o *OpSpReg) MarshalJSON() ([]byte, error) {
	tmp := make([]byte, base64.StdEncoding.EncodedLen(len(o.Val)))
	base64.StdEncoding.Encode(tmp, o.Val)

	out := append(strconv.AppendUint([]byte(`{"op":`), OP_SPREG, 10), []byte(`,"num":`)...)
	out = append(strconv.AppendUint(out, uint64(o.Num), 10), []byte(`,"val":"`)...)
	return append(append(out, tmp...), []byte(`"}`)...), nil
}

func (o *OpMemRead) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_MEM_READ, 10), []byte(`,"addr":`)...)
	out = append(strconv.AppendUint(out, o.Addr, 10), []byte(`,"size":`)...)
	return append(strconv.AppendUint(out, uint64(o.Size), 10), '}'), nil
}

func (o *OpMemWrite) MarshalJSON() ([]byte, error) {
	tmp := make([]byte, base64.StdEncoding.EncodedLen(len(o.Data)))
	base64.StdEncoding.Encode(tmp, o.Data)

	out := append(strconv.AppendUint([]byte(`{"op":`), OP_MEM_WRITE, 10), []byte(`,"addr":`)...)
	out = append(strconv.AppendUint(out, o.Addr, 10), []byte(`,"data":"`)...)
	return append(append(out, tmp...), []byte(`"}`)...), nil
}

func (o *OpMemMap) MarshalJSON() ([]byte, error) {
	desc, _ := json.Marshal(o.Desc)
	file, _ := json.Marshal(o.File)
	out := strconv.AppendUint([]byte(`{"op":`), OP_MEM_MAP, 10)
	out = append(append(out, []byte(`,"desc":`)...), desc...)
	out = append(append(out, []byte(`,"file":`)...), file...)

	out = strconv.AppendUint(append(out, []byte(`,"off":`)...), o.Off, 10)
	return append(strconv.AppendUint(append(out, []byte(`,"len":`)...), o.Len, 10), '}'), nil
}

func (o *OpMemUnmap) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_MEM_UNMAP, 10), []byte(`,"addr":`)...)
	out = append(strconv.AppendUint(out, o.Addr, 10), []byte(`,"size":`)...)
	return append(strconv.AppendUint(out, uint64(o.Size), 10), '}'), nil
}

func (o *OpMemProt) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_MEM_PROT, 10), []byte(`,"addr":`)...)
	out = append(strconv.AppendUint(out, o.Addr, 10), []byte(`,"size":`)...)
	out = append(strconv.AppendUint(out, uint64(o.Size), 10), []byte(`,"prot":`)...)
	return append(strconv.AppendUint(out, uint64(o.Prot), 10), '}'), nil
}

func (o *OpSyscall) MarshalJSON() ([]byte, error) {
	var args []byte
	for i, v := range o.Args {
		args = strconv.AppendUint(args, v, 10)
		if i < len(o.Args)-1 {
			args = append(args, ',')
		}
	}
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_SYSCALL, 10), []byte(`,"args":[`)...)
	out = append(append(out, args...), []byte(`],"ret":`)...)
	out = append(strconv.AppendUint(out, o.Ret, 10), []byte(`,"ops":[`)...)
	return append(append(out, marshalOps(o.Ops)...), []byte(`]}`)...), nil
}

func (o *OpKeyframe) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_KEYFRAME, 10), []byte(`,"pid":`)...)
	out = append(strconv.AppendUint(out, uint64(o.Pid), 10), []byte(`,"ops":[`)...)
	return append(append(out, marshalOps(o.Ops)...), []byte(`]}`)...), nil
}

func (o *OpFrame) MarshalJSON() ([]byte, error) {
	out := append(strconv.AppendUint([]byte(`{"op":`), OP_FRAME, 10), []byte(`,"pid":`)...)
	out = append(strconv.AppendUint(out, uint64(o.Pid), 10), []byte(`,"ops":[`)...)
	return append(append(out, marshalOps(o.Ops)...), []byte(`]}`)...), nil
}
