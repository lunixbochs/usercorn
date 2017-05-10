package trace

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type msp map[string]interface{}

func bprintf(f string, args ...interface{}) []byte {
	return []byte(fmt.Sprintf(f, args...))
}

func (o *OpNop) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d}`, OP_NOP), nil
}

func (o *OpExit) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d}`, OP_EXIT), nil
}

func (o *OpJmp) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d,"addr":%d,"size":%d}`, OP_JMP, o.Addr, o.Size), nil
}

func (o *OpStep) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d,"size":%d}`, OP_STEP, o.Size), nil
}

func (o *OpReg) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d,"num":%d,"val":%d}`, OP_REG, o.Num, o.Val), nil
}

func (o *OpSpReg) MarshalJSON() ([]byte, error) {
	val := base64.StdEncoding.EncodeToString(o.Val)
	return bprintf(`{"op":%d,"num":%d,"val":"%s"}`, OP_SPREG, o.Num, val), nil
}

func (o *OpMemRead) MarshalJSON() ([]byte, error) {
	data := base64.StdEncoding.EncodeToString(o.Data)
	return bprintf(`{"op":%d,"addr":%d,"data":"%s"}`, OP_MEM_READ, o.Addr, data), nil
}

func (o *OpMemWrite) MarshalJSON() ([]byte, error) {
	data := base64.StdEncoding.EncodeToString(o.Data)
	return bprintf(`{"op":%d,"addr":%d,"data":"%s"}`, OP_MEM_WRITE, o.Addr, data), nil
}

func (o *OpMemMap) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d,"addr":%d,"size":%d,"prot":%d,"zero":%d}`, OP_MEM_MAP, o.Addr, o.Size, o.Prot, o.Zero), nil
}

func (o *OpMemUnmap) MarshalJSON() ([]byte, error) {
	return bprintf(`{"op":%d,"addr":%d,"size":%d}`, OP_MEM_UNMAP, o.Addr, o.Size), nil
}

func (o *OpSyscall) MarshalJSON() ([]byte, error) {
	args, err := json.Marshal(o.Args)
	if err != nil {
		return nil, err
	}
	ops, err := json.Marshal(o.Ops)
	if err != nil {
		return nil, err
	}
	return bprintf(`{"op":%d,"args":%s,"ret":%d,"ops":%s}`, OP_SYSCALL, args, o.Ret, ops), nil
}

func (o *OpKeyframe) MarshalJSON() ([]byte, error) {
	ops, err := json.Marshal(o.Ops)
	if err != nil {
		return nil, err
	}
	return bprintf(`{"op":%d,"ops":%s}`, OP_KEYFRAME, ops), nil
}

func (o *OpFrame) MarshalJSON() ([]byte, error) {
	ops, err := json.Marshal(o.Ops)
	if err != nil {
		return nil, err
	}
	return bprintf(`{"op":%d,"ops":%s}`, OP_FRAME, ops), nil
}
