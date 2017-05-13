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
	pc       int

	regs    []uint64
	hooks   []cpu.Hook
	sysHook *models.SysHook
	mapHook *models.MapHook

	keyframe *keyframe
	frame    *OpFrame
	syscall  *OpSyscall
	op       models.Op

	u      models.Usercorn
	w      io.WriteCloser
	tf     *TraceWriter
	config *models.TraceConfig

	attached bool
}

func NewTrace(u models.Usercorn, config *models.TraceConfig) (*Trace, error) {
	enums := u.Arch().RegEnums()
	t := &Trace{
		u:        u,
		config:   config,
		regEnums: enums,
		pc:       u.Arch().PC,
		keyframe: &keyframe{regEnums: enums},
	}
	t.keyframe.reset()

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
		mo := &OpMemMap{Addr: m.Addr, Size: m.Size, Prot: uint8(m.Prot)}
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
			if t.config.Reg {
				t.OnRegUpdate()
			}
			t.OnStep(size)
		}, 1, 0); err != nil {
			return err
		}
	}
	if t.config.Mem {
		if err := t.hook(cpu.HOOK_MEM_READ|cpu.HOOK_MEM_WRITE,
			func(_ cpu.Cpu, access int, addr uint64, size int, val int64) {
				if access == cpu.MEM_WRITE {
					var data []byte
					var tmp [8]byte
					e := t.u.ByteOrder()
					switch size {
					case 1:
						tmp[0] = uint8(val)
						data = tmp[:1]
					case 2:
						e.PutUint16(tmp[:], uint16(val))
						data = tmp[:2]
					case 4:
						e.PutUint32(tmp[:], uint32(val))
						data = tmp[:4]
					case 8:
						e.PutUint64(tmp[:], uint64(val))
						data = tmp[:8]
					}
					t.OnMemWrite(addr, data)
				} else {
					t.OnMemRead(addr, size)
				}
			}, 1, 0); err != nil {
			return err
		}
		mmapHook := func(addr, size uint64, prot int, zero bool) {
			t.OnMemMap(addr, size, prot, zero)
		}
		munmapHook := func(addr, size uint64) {
			t.OnMemUnmap(addr, size)
		}
		t.mapHook = t.u.HookMapAdd(mmapHook, munmapHook)
	}
	if t.config.Sys {
		// TODO: where are keyframes?
		// idea: could write keyframes backwards while tracking dirty addrs
		// this will prevent repeated writes from doing anything
		// TODO: "push/pop" syscall frames?
		before := func(num int, args []uint64, ret uint64) {
			t.OnSysPre(num, args, ret)
		}
		after := func(num int, args []uint64, ret uint64) {
			t.OnSysPost(num, args, ret)
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
	if t.syscall != nil {
		t.Send(t.syscall)
		t.syscall = nil
	}
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
	if t.config.OpCallback != nil {
		t.config.OpCallback(op)
	}
}

func (t *Trace) Pack(frame *OpFrame) {
	if frame != nil {
		if t.tf != nil {
			t.tf.Pack(frame)
		}
	}
}

// canAdvance indicates whether this op can start a new keyframe
// TODO: eventually allow alternating OpFrames with Syscalls, like on windows kernel->userspace callbacks?
func (t *Trace) Append(op models.Op, canAdvance bool) {
	t.Send(op)
	// TODO: add stuff to keyframe
	frame := t.frame
	// handle the first frame
	if frame == nil || t.syscall == nil && canAdvance {
		t.Pack(frame)
		t.frame = &OpFrame{Ops: []models.Op{op}}
	} else if t.syscall != nil {
		t.syscall.Ops = append(t.syscall.Ops, op)
	} else {
		t.frame.Ops = append(t.frame.Ops, op)
	}
}

// trace hooks are below

func (t *Trace) OnJmp(addr uint64, size uint32) {
	t.Append(&OpJmp{Addr: addr, Size: size}, true)
}
func (t *Trace) OnStep(size uint32) {
	t.Append(&OpStep{Size: uint8(size)}, false)
}

func (t *Trace) OnRegUpdate() {
	regs, _ := t.u.Arch().RegDumpFast(t.u)
	for i, val := range regs {
		if t.regs[i] != val && t.regEnums[i] != t.pc {
			t.Append(&OpReg{Num: uint16(t.regEnums[i]), Val: val}, false)
			t.regs[i] = val
		}
	}
}

func (t *Trace) OnMemReadData(addr uint64, data []byte) {
	t.Append(&OpMemRead{addr, data}, false)
}

func (t *Trace) OnMemRead(addr uint64, size int) {
	// TODO: error tracking?
	data, err := t.u.MemRead(addr, uint64(size))
	if err == nil {
		t.OnMemReadData(addr, data)
	}
}

func (t *Trace) OnMemWrite(addr uint64, data []byte) {
	t.Append(&OpMemWrite{addr, data}, false)
}

func (t *Trace) OnMemMap(addr, size uint64, prot int, zero bool) {
	zint := 0
	if zero {
		zint = 1
	}
	t.Append(&OpMemMap{addr, size, uint8(prot), uint8(zint)}, false)
}

func (t *Trace) OnMemUnmap(addr, size uint64) {
	t.Append(&OpMemUnmap{addr, size}, false)
}

func (t *Trace) OnSysPre(num int, args []uint64, ret uint64) {
	syscall := &OpSyscall{uint32(num), 0, args, nil}
	// TODO: how to add syscall to keyframe?
	t.Append(syscall, false)
	t.syscall = syscall
}

func (t *Trace) OnSysPost(num int, args []uint64, ret uint64) {
	if t.syscall != nil {
		t.syscall.Ret = ret
		t.syscall = nil
	}
}

func (t *Trace) OnExit() {
	t.Append(&OpExit{}, false)
}
