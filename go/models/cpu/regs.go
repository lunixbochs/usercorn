package cpu

import (
	"github.com/pkg/errors"
)

// implements register and context methods conforming to cpu.Cpu
// TODO: maps are slow.
// []uint64 would be faster, but enum lookups would require a second []bool (to check if an enum is valid)
// and the array size could become very large if someone uses a large enum
// another option would be to switch between map and array based on max enum
// and yet another would be to reject too-large enums (force uint16 in initialization?)
type Regs struct {
	mask uint64
	vals map[int]uint64
}

func NewRegs(bits uint, enums []int) *Regs {
	r := &Regs{
		mask: ^uint64(0) >> (64 - bits),
		vals: make(map[int]uint64),
	}
	for _, e := range enums {
		r.vals[e] = 0
	}
	return r
}

func (r *Regs) RegRead(enum int) (uint64, error) {
	if val, ok := r.vals[enum]; !ok {
		return 0, errors.New("invalid register")
	} else {
		return val, nil
	}
}

func (r *Regs) RegWrite(enum int, val uint64) error {
	val &= r.mask
	if _, ok := r.vals[enum]; !ok {
		return errors.New("invalid register")
	}
	r.vals[enum] = val
	return nil
}

// handling ContextSave in the register file either requires you to store important cpu state (like flags) in registers
// or wrap ContextSave/ContextRestore with your own functions
func (r *Regs) ContextSave(reuse interface{}) (interface{}, error) {
	var m map[int]uint64
	if reuse != nil {
		var ok bool
		if m, ok = reuse.(map[int]uint64); !ok {
			return nil, errors.New("incorrect context type")
		}
	} else {
		m = make(map[int]uint64)
	}
	for k, v := range r.vals {
		m[k] = v
	}
	return m, nil
}

func (r *Regs) ContextRestore(ctx interface{}) error {
	if m, ok := ctx.(map[int]uint64); !ok {
		return errors.New("incorrect context type")
	} else {
		for k, v := range m {
			r.vals[k] = v
		}
		return nil
	}
}
