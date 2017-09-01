package trace

import (
	"fmt"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

// OpMemBatch is a collection of reads and writes that occured within a basic block
type OpMemBatch struct {
	OpNop
	Ops []models.Op
}

func (o *OpMemBatch) Render(mem *cpu.Mem) string {
	var out []string
	for _, op := range o.Ops {
		var addr uint64
		var data []byte
		var t string
		switch v := op.(type) {
		case *OpMemWrite:
			addr, data, t = v.Addr, v.Data, "W"
		case *OpMemRead:
			addr = v.Addr
			data, _ = mem.MemRead(v.Addr, uint64(v.Size))
			t = "R"
		}

		for i, line := range models.HexDump(addr, data, 32) {
			if i == 0 {
				out = append(out, fmt.Sprintf("%s %s %s\n", t, line, t))
			} else {
				out = append(out, fmt.Sprintf("   %s\n", line))
			}
		}
	}
	return strings.Join(out, "")
}

type MemBatch struct {
	memOps []models.Op
}

func (m *MemBatch) Filter(op models.Op) []models.Op {
	switch op.(type) {
	case *OpJmp:
		return append(m.Flush(), op)
	case *OpMemRead, *OpMemWrite:
		m.memOps = append(m.memOps, op)
	}
	return []models.Op{op}
}

func (m *MemBatch) Flush() []models.Op {
	log := &MemLog{}

	// Build a log of all reads and writes
	for _, op := range m.memOps {
		switch v := op.(type) {
		case *OpMemWrite:
			log.Update(v.Addr, uint32(len(v.Data)), v.Data, true)
		case *OpMemRead:
			log.Update(v.Addr, v.Size, nil, false)
		}
	}
	m.memOps = nil
	ops := make([]models.Op, 0, len(log.log))
	for _, d := range log.log {
		if d.write {
			ops = append(ops, &OpMemWrite{d.addr, d.data})
		} else {
			ops = append(ops, &OpMemRead{d.addr, d.size})
		}
	}
	return []models.Op{&OpMemBatch{Ops: ops}}
}

type memDelta struct {
	addr  uint64
	last  []byte
	data  []byte
	size  uint32
	write bool
	tag   byte
}

type MemLog struct {
	log []*memDelta
}

// TODO: instead of using byte equivalence for Adjacent
// writing to an addr should update the addr's version
// adjacency for both read and write only works if you're on the same version
// right now, you can have an adjacent op to an older log entry and cause ordering confusion
func (m *MemLog) Adjacent(addr uint64, size uint32, write bool) *memDelta {
	for _, delta := range m.log {
		if delta.write != write {
			continue
		}
		if addr == delta.addr+uint64(len(delta.data)) || addr == delta.addr-uint64(size) {
			return delta
		}
	}
	return nil
}

// Update inserts a new read or write event into the log
func (m *MemLog) Update(addr uint64, size uint32, p []byte, write bool) {
	var delta *memDelta
	before := false
	if delta = m.Adjacent(addr, size, write); delta != nil {
		if addr < delta.addr {
			delta.addr -= uint64(len(p))
			before = true
		}
		var tag byte
		if before {
			tag = '<'
		} else {
			tag = '>'
		}
		if delta.tag == ' ' {
			delta.tag = tag
		} else if delta.tag != tag {
			delta.tag = '~'
		}
	} else {
		// entirely new memory delta
		delta = &memDelta{addr, nil, nil, 0, write, ' '}
		m.log = append(m.log, delta)
	}
	if write {
		if before {
			data := make([]byte, len(p), len(p)+len(delta.data))
			copy(data, p)
			copy(data[len(p):], delta.data)
			delta.data = data
			delta.last = delta.data[:len(p)]
		} else {
			delta.data = append(delta.data, p...)
			delta.last = delta.data[len(delta.data)-len(p):]
		}
	}
	delta.size += size
}

func (m *MemLog) String(bits int) string {
	var out []string
	for _, d := range m.log {
		t := "R"
		if d.write {
			t = "W"
		}
		for i, line := range models.HexDump(d.addr, d.data, bits) {
			if i == 0 {
				out = append(out, fmt.Sprintf("%s%c %s %s%c\n", t, d.tag, line, t, d.tag))
			} else {
				out = append(out, fmt.Sprintf("   %s\n", line))
			}
		}
	}
	return strings.Join(out, "")
}
