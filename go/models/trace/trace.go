package trace

import (
	"bytes"
	"github.com/pkg/errors"
	"io"
	"os"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Trace struct {
	regEnums []int
	pcReg    int

	regs    []uint64
	hooks   []cpu.Hook
	sysHook *models.SysHook
	mapHook *models.MapHook

	keyframe *keyframe
	frame    *OpFrame
	syscall  *OpSyscall
	op       models.Op
	step     *OpStep
	stepAddr uint64

	u      models.Usercorn
	w      io.WriteCloser
	tf     *TraceWriter
	config *models.TraceConfig

	filters []models.Filter

	attached  bool
	firstStep bool
}

func NewTrace(u models.Usercorn, config *models.TraceConfig) (*Trace, error) {
	enums := u.Arch().RegEnums()
	t := &Trace{
		u:        u,
		config:   config,
		regEnums: enums,
		pcReg:    u.Arch().PC,
		keyframe: &keyframe{regEnums: enums},
	}
	t.keyframe.reset()

	if config.MemBatch {
		t.filters = append(t.filters, &MemBatch{})
	}
	var err error
	t.w = config.TraceWriter
	if t.w == nil && config.Tracefile != "" {
		if t.w, err = os.Create(config.Tracefile); err != nil {
			return nil, errors.Wrapf(err, "failed to create tracefile '%s'", config.Tracefile)
		}
	}
	if t.w != nil {
		if t.tf, err = NewWriter(t.w, u); err != nil {
			return nil, errors.Wrap(err, "failed to create trace writer")
		}
	}
	return t, nil
}

func (t *Trace) hook(enum int, f interface{}, begin, end uint64) error {
	hh, err := t.u.HookAdd(enum, f, begin, end)
	if err != nil {
		return errors.Wrap(err, "u.HookAdd failed")
	}
	t.hooks = append(t.hooks, hh)
	return nil
}

func (t *Trace) Attach() error {
	if t.attached {
		return nil
	}
	t.attached = true
	t.regs = make([]uint64, len(t.regEnums))
	// make a keyframe to catch up (temporary frame is created so we can call OnRegUpdate)
	t.frame = &OpFrame{}
	t.OnRegUpdate()
	kf := &OpKeyframe{Ops: t.frame.Ops}
	t.frame = nil
	for _, m := range t.u.Mappings() {
		mo := &OpMemMap{Addr: m.Addr, Size: m.Size, Prot: uint8(m.Prot), New: true, Desc: m.Desc}
		if m.File != nil {
			mo.File = m.File.Name
			mo.Off = m.File.Off
		}
		kf.Ops = append(kf.Ops, mo)
		data, err := t.u.MemRead(m.Addr, m.Size)
		if err != nil {
			return errors.Wrapf(err, "failed to read initial memory mapping at %#x", m.Addr)
		}
		data = bytes.Trim(data, "\x00")
		mw := &OpMemWrite{Addr: m.Addr, Data: data}
		kf.Ops = append(kf.Ops, mw)
	}
	if t.tf != nil {
		t.tf.Pack(kf)
	}
	// send keyframe to UI to set initial state
	t.Send(kf)

	if t.config.Block || t.config.Ins || t.config.Reg || t.config.SpecialReg {
		if err := t.hook(cpu.HOOK_BLOCK, func(_ cpu.Cpu, addr uint64, size uint32) {
			if t.config.Reg && !t.config.Ins {
				t.OnRegUpdate()
			}
			if t.config.Block || t.config.Ins {
				t.OnJmp(addr, size)
			}
		}, 1, 0); err != nil {
			return err
		}
	}
	if t.config.Ins {
		if err := t.hook(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
			t.OnStep(addr, size)
		}, 1, 0); err != nil {
			return err
		}
	}
	if t.config.Mem {
		if err := t.hook(cpu.HOOK_MEM_READ|cpu.HOOK_MEM_WRITE,
			func(_ cpu.Cpu, access int, addr uint64, size int, val int64) {
				if access == cpu.MEM_WRITE {
					var tmp [8]byte
					// FIXME? error swallowed
					data, _ := cpu.PackUint(t.u.ByteOrder(), size, tmp[:], uint64(val))
					t.OnMemWrite(addr, data)
				} else {
					t.OnMemRead(addr, size)
				}
			}, 1, 0); err != nil {
			return err
		}
		t.mapHook = t.u.HookMapAdd(t.OnMemMap, t.OnMemUnmap)
	}
	if t.config.Sys {
		// TODO: where are keyframes?
		// idea: could write keyframes backwards while tracking dirty addrs
		// this will prevent repeated writes from doing anything
		// TODO: "push/pop" syscall frames?
		before := func(num int, args []uint64, ret uint64, desc string) {
			t.OnSysPre(num, args, ret, desc)
		}
		after := func(num int, args []uint64, ret uint64, desc string) {
			t.OnSysPost(num, args, ret, desc)
		}
		t.sysHook = t.u.HookSysAdd(before, after)
	}
	return nil
}

func (t *Trace) Detach() {
	if !t.attached {
		return
	}
	t.attached = false
	// TODO: flush last frame on detach (make sure to detach on the way out)
	t.flushStep()
	if t.frame != nil {
		t.Pack(t.frame)
		t.frame = nil
	}
	if t.tf != nil {
		t.tf.Close()
		t.tf = nil
	}

	for _, hh := range t.hooks {
		t.u.HookDel(hh)
	}
	t.hooks = nil
	if t.sysHook != nil {
		t.u.HookSysDel(t.sysHook)
		t.sysHook = nil
	}
	if t.mapHook != nil {
		t.u.HookMapDel(t.mapHook)
		t.mapHook = nil
	}
	t.regs = nil
}

// this gets weird, because I want to stream some things instruction-at-a-time
// but also want all of the frame information for printing where possible
// and on the middle ground, I want register information for an instruction
// I guess everything between an OpStep/OpJmp goes to the next OpStep/Jmp?
func (t *Trace) Send(op models.Op) {
	for _, cb := range t.config.OpCallback {
		cb(op)
	}
}

func (t *Trace) Pack(frame *OpFrame) {
	if frame != nil {
		if t.tf != nil {
			t.tf.Pack(frame)
		}
	}
}

// keyframes will be all messed up now
func (t *Trace) Rewound() {
	t.step = nil
	t.stepAddr = 0
	// it's a reg update without sending any ops
	regs, _ := t.u.Arch().RegDumpFast(t.u)
	for i, val := range regs {
		if t.regs[i] != val && t.regEnums[i] != t.pcReg {
			t.regs[i] = val
		}
	}
}

// canAdvance indicates whether this op can start a new keyframe
// TODO: eventually allow alternating OpFrames with Syscalls, like on windows kernel->userspace callbacks?
func (t *Trace) Append(op models.Op, canAdvance bool) {
	ops := []models.Op{op}
	// workaround (syscall's ops should be filtered in isolation, which needs a "filter all of these ops at once" function)
	if t.syscall == nil {
		for _, filter := range t.filters {
			var filteredOps []models.Op
			for _, op := range ops {
				filteredOps = append(filteredOps, filter.Filter(op)...)
			}
			ops = filteredOps
		}
	}
	for _, op := range ops {
		// TODO: add stuff to keyframe
		frame := t.frame
		// handle the first frame
		_, isStep := op.(*OpStep)
		if frame == nil || t.syscall == nil && canAdvance {
			t.Pack(frame)
			t.frame = &OpFrame{Ops: []models.Op{op}}
			t.Send(op)
		} else if t.syscall != nil && !isStep {
			t.syscall.Ops = append(t.syscall.Ops, op)
		} else {
			t.frame.Ops = append(t.frame.Ops, op)
			t.Send(op)
		}
		canAdvance = false
	}
}

// trace hooks are below
func (t *Trace) flushStep() {
	sys := t.syscall
	t.syscall = nil
	// we need to lag one instruction behind, because OnStep is *before* the instruction
	if t.step != nil {
		t.OnRegUpdate()
		t.Append(t.step, false)
		t.step = nil
	}
	t.flushSys(sys)
}

func (t *Trace) flushSys(sys *OpSyscall) {
	if sys != nil {
		t.syscall = nil
		t.Append(sys, false)
	}
}

func (t *Trace) OnJmp(addr uint64, size uint32) {
	// TODO: handle real self-jumps?
	if t.step != nil && addr != t.stepAddr {
		t.flushStep()
	}
	t.Append(&OpJmp{Addr: addr, Size: size}, true)
}

func (t *Trace) OnStep(addr uint64, size uint32) {
	if addr == t.stepAddr {
		return
	}
	t.flushStep()
	t.step = &OpStep{Size: uint8(size)}
	t.stepAddr = addr
}

func (t *Trace) OnRegUpdate() {
	regs, _ := t.u.Arch().RegDumpFast(t.u)
	for i, val := range regs {
		if t.regs[i] != val && t.regEnums[i] != t.pcReg {
			t.Append(&OpReg{Num: uint16(t.regEnums[i]), Val: val}, false)
			t.regs[i] = val
		}
	}
}

func (t *Trace) OnMemReadSize(addr uint64, size uint32) {
	t.Append(&OpMemRead{addr, size}, false)
}

func (t *Trace) OnMemRead(addr uint64, size int) {
	t.OnMemReadSize(addr, uint32(size))
}

func (t *Trace) OnMemWrite(addr uint64, data []byte) {
	t.Append(&OpMemWrite{addr, data}, false)
}

func (t *Trace) OnMemMap(addr, size uint64, prot int, new bool, desc string, file *cpu.FileDesc) {
	var name string
	var off uint64
	if file != nil {
		name, off = file.Name, file.Off
	}
	t.Append(&OpMemMap{addr, size, uint8(prot), new, desc, name, off}, false)
}

func (t *Trace) OnMemUnmap(addr, size uint64) {
	t.Append(&OpMemUnmap{addr, size}, false)
}

func (t *Trace) OnSysPre(num int, args []uint64, ret uint64, desc string) {
	t.flushSys(t.syscall)
	// TODO: how to add syscall to keyframe?
	t.syscall = &OpSyscall{uint32(num), 0, args, desc, nil}
}

func (t *Trace) OnSysPost(num int, args []uint64, ret uint64, desc string) {
	sys := t.syscall
	if sys != nil {
		sys.Desc += desc
		sys.Ret = ret
		t.OnRegUpdate()
	}
}

func (t *Trace) OnExit() {
	t.Append(&OpExit{}, false)
}
