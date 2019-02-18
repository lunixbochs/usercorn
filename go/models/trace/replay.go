package trace

import (
	"container/list"
	"encoding/binary"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
	"github.com/lunixbochs/usercorn/go/models/debug"
)

type Replay struct {
	Arch   *models.Arch
	OS     *models.OS
	Mem    *cpu.Mem
	Regs   map[int]uint64
	SpRegs map[int][]byte
	PC, SP uint64

	Callstack models.Callstack
	Debug     *debug.Debug
	Inscount  uint64
	// pending is an OpStep representing the last unflushed instruction. Cleared by Flush().
	pending   *OpStep
	effects   []models.Op
	callbacks []func(models.Op, []models.Op)

	History   *list.List
	CanRewind bool
}

func NewReplay(arch *models.Arch, os *models.OS, order binary.ByteOrder, dbg *debug.Debug) *Replay {
	return &Replay{
		Arch:    arch,
		OS:      os,
		Mem:     cpu.NewMem(uint(arch.Bits), order),
		Regs:    make(map[int]uint64),
		SpRegs:  make(map[int][]byte),
		Debug:   dbg,
		History: list.New(),
	}
}

func (r *Replay) Listen(cb func(models.Op, []models.Op)) {
	r.callbacks = append(r.callbacks, cb)
}

func (r *Replay) Rewind(by, addr uint64) error {
	if !r.CanRewind {
		return errors.New("rewind is not enabled")
	}
	return nil
}

func (r *Replay) pushMapUndo(addr, size uint64) {
	for _, mm := range r.Mem.Maps().FindRange(addr, size) {
		if addr, size, ok := mm.Intersect(addr, size); ok {
			page := mm.Slice(addr, size)
			op := &OpMemMap{Addr: page.Addr, Size: page.Size, Prot: uint8(mm.Prot), Desc: page.Desc}
			if page.File != nil {
				op.File = page.File.Name
				op.Off = page.File.Off
				op.Len = page.File.Len
			}
			r.History.PushBack(op)
			data, _ := r.Mem.MemRead(addr, size)
			r.History.PushBack(&OpMemWrite{addr, data})
		}
	}
}

// creates "undo operations" and adds them to the History list
func (r *Replay) pushUndo(op models.Op) {
	switch o := op.(type) {
	case *OpJmp: // code
		r.History.PushBack(&OpJmp{r.PC, 0})
	case *OpStep:
		// will just reverse the meaning of step on replay
		r.History.PushBack(o)

	case *OpReg: // register
		r.History.PushBack(&OpReg{Num: o.Num, Val: r.Regs[int(o.Num)]})
	case *OpSpReg:
		r.History.PushBack(&OpSpReg{Num: o.Num, Val: r.SpRegs[int(o.Num)]})

		// all memory unwind ops need a list of old overlapping regions
		// they should make sure the list of regions post-rewind is identical, and has the same contents
	case *OpMemMap: // memory
		r.History.PushBack(&OpMemUnmap{o.Addr, o.Size})
		r.pushMapUndo(o.Addr, o.Size)
	case *OpMemUnmap:
		r.pushMapUndo(o.Addr, o.Size)
	case *OpMemProt:
		// this should walk the regions and set old protections
		for _, mm := range r.Mem.Maps().FindRange(o.Addr, o.Size) {
			r.History.PushBack(&OpMemProt{mm.Addr, mm.Size, uint8(mm.Prot)})
		}
	case *OpMemWrite:
		data, _ := r.Mem.MemRead(o.Addr, uint64(len(o.Data)))
		r.History.PushBack(&OpMemWrite{o.Addr, data})
	}
}

// update() applies state change(s) from op to the Replay's internal state
func (r *Replay) update(op models.Op) {
	if r.CanRewind {
		r.pushUndo(op)
	}
	switch o := op.(type) {
	case *OpJmp: // code
		r.PC = o.Addr
	case *OpStep:
		r.PC += uint64(o.Size)

	case *OpReg: // register
		if int(o.Num) == r.Arch.SP {
			r.SP = o.Val
			r.Callstack.Update(r.PC, r.SP)
		}
		r.Regs[int(o.Num)] = o.Val
	case *OpSpReg:
		r.SpRegs[int(o.Num)] = o.Val

	case *OpMemMap: // memory
		// TODO: can this be changed to not need direct access to Sim?
		page := r.Mem.Sim.Map(o.Addr, uint64(o.Size), int(o.Prot), true)
		page.Desc = o.Desc
		if o.File != "" {
			page.File = &cpu.FileDesc{Name: o.File, Off: o.Off, Len: o.Len}
		}
	case *OpMemUnmap:
		r.Mem.MemUnmap(o.Addr, uint64(o.Size))
	case *OpMemProt:
		r.Mem.MemProt(o.Addr, uint64(o.Size), int(o.Prot))
	case *OpMemWrite:
		r.Mem.MemWrite(o.Addr, o.Data)

	case *OpSyscall:
		for _, v := range o.Ops {
			r.update(v)
		}
	}
}

// Feed is the entry point handling Op structs.
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
			// fixes a bug where single-stepping misattributes registers
			if o.Addr != r.PC {
				r.Flush()
			}
			r.Emit(o, nil)
			r.update(o)
		case *OpStep:
			r.Flush()
			r.pending = o
		case *OpSyscall:
			r.Flush()
			r.update(o)
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

func (r *Replay) Symbolicate(addr uint64, includeSource bool) (*models.Symbol, string) {
	return r.Debug.Symbolicate(addr, r.Mem.Maps(), includeSource)
}
