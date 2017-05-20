package trace

import (
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Replay struct {
	Arch   *models.Arch
	OS     *models.OS
	Mem    *cpu.MemSim
	Regs   map[int]uint64
	SpRegs map[int][]byte
	PC, SP uint64

	Inscount uint64
	// pending is an OpStep representing the last unflushed instruction. Cleared by Flush().
	pending   *OpStep
	effects   []models.Op
	callbacks []func(models.Op, []models.Op)
}

func NewReplay(arch *models.Arch, os *models.OS) *Replay {
	return &Replay{
		Arch:   arch,
		OS:     os,
		Mem:    &cpu.MemSim{},
		Regs:   make(map[int]uint64),
		SpRegs: make(map[int][]byte),
	}
}

func (r *Replay) Listen(cb func(models.Op, []models.Op)) {
	r.callbacks = append(r.callbacks, cb)
}

// update() applies state change(s) from op to the UI's internal state
func (r *Replay) update(op models.Op) {
	switch o := op.(type) {
	case *OpJmp: // code
		r.PC = o.Addr
	case *OpStep:
		r.PC += uint64(o.Size)

	case *OpReg: // register
		if int(o.Num) == r.Arch.SP {
			r.SP = o.Val
		}
		r.Regs[int(o.Num)] = o.Val
	case *OpSpReg:
		r.SpRegs[int(o.Num)] = o.Val

	case *OpMemMap: // memory
		r.Mem.Map(o.Addr, uint64(o.Size), int(o.Prot), o.Zero != 0)
	case *OpMemUnmap:
		r.Mem.Unmap(o.Addr, uint64(o.Size))
	case *OpMemWrite:
		r.Mem.Write(o.Addr, o.Data, 0)

	case *OpSyscall:
		for _, v := range o.Ops {
			r.update(v)
		}
	}
}

// Feed() is the entry point handling Op structs.
// It calls update() and combines side-effects with instructions
func (r *Replay) Feed(op models.Op) {
	var ops []models.Op
	switch o := op.(type) {
	case *OpFrame:
		ops = o.Ops
	default:
		ops = []models.Op{op}

	case *OpKeyframe:
		// we need to flush here, because the keyframe can change state we need to emit
		r.Flush()
		// We only need the first keyframe for simple display (until we're doing rewind/ff)
		// but it probably doesn't hurt too much for now to always process keyframes... just don't emit them
		for _, v := range o.Ops {
			r.update(v)
		}
		return
	}

	for _, op := range ops {
		// batch everything until we hit an OpJmp or OpStep
		// at that point, flush the last OpStep
		switch o := op.(type) {
		case *OpJmp:
			r.Flush()
			r.Emit(o, nil)
			r.update(o)
		case *OpStep:
			r.Flush()
			r.pending = o
		case *OpSyscall:
			r.Flush()
			r.Emit(o, o.Ops)
		default:
			// queue everything else as side-effects
			r.effects = append(r.effects, op)
		}
	}
	// flush at end of frame too, so repl isn't an instruction behind when single stepping
	r.Flush()
}

func (r *Replay) Emit(op models.Op, effects []models.Op) {
	for _, cb := range r.callbacks {
		cb(op, effects)
	}
}

func (r *Replay) Flush() {
	if r.pending != nil {
		r.Emit(r.pending, r.effects)
		r.Inscount += 1
		r.update(r.pending)
		for _, op := range r.effects {
			r.update(op)
		}
		r.effects = r.effects[:0]
		r.pending = nil
	}
}
