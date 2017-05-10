package trace

import (
	"github.com/lunixbochs/usercorn/go/models"
)

type keyframe struct {
	regEnums []int
	regs     []uint64
	spregs   map[int][]byte
	writes   map[uint64][]byte

	// this is both maps and unmaps to ensure they stay in order
	maps []models.Op
}

func (k *keyframe) reset() {
	k.regs = make([]uint64, len(k.regEnums))
	k.spregs = make(map[int][]byte)
	k.writes = make(map[uint64][]byte)
	k.maps = nil
}

func (k *keyframe) op() *OpKeyframe {
	frame := &OpKeyframe{}
	frame.Ops = k.maps
	for i, reg := range k.regs {
		op := &OpReg{Num: uint16(k.regEnums[i]), Val: reg}
		frame.Ops = append(frame.Ops, op)
	}
	// TODO handle spregs
	for addr, data := range k.writes {
		op := &OpMemWrite{Addr: addr, Data: data}
		frame.Ops = append(frame.Ops, op)
	}
	return frame
}
