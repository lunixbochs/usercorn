package trace

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

// OpMemBatch is a collection of reads and writes that occured within a basic block
type OpMemBatch struct {
	models.NoOp
	Ops []models.Op
}

func (o *OpMemBatch) String() string {
	var out []string
	for _, op := range o.Ops {
		var addr uint64
		var data []byte
		var t string
		switch v := op.(type) {
		case *OpMemWrite:
			addr, data, t = v.Addr, v.Data, "W"
		case *OpMemRead:
			addr, data, t = v.Addr, v.Data, "R"
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
			log.Update(v.Addr, v.Data, true)
		case *OpMemRead:
			log.Update(v.Addr, v.Data, false)
		}
	}
	m.memOps = nil
	ops := make([]models.Op, 0, len(log.log))
	for _, d := range log.log {
		if d.write {
			ops = append(ops, &OpMemWrite{d.addr, d.data})
		} else {
			ops = append(ops, &OpMemRead{d.addr, d.data})
		}
	}
	return []models.Op{&OpMemBatch{Ops: ops}}
}

type memDelta struct {
	addr  uint64
	last  []byte
	data  []byte
	write bool
	tag   byte
}

type MemLog struct {
	log []*memDelta
}

func (m *MemLog) Adjacent(addr uint64, p []byte, write bool) (delta *memDelta, dup bool) {
	for _, delta := range m.log {
		if delta.write != write {
			continue
		}
		if addr == delta.addr && bytes.Equal(p, delta.last) {
			return delta, true
		}
		if addr == delta.addr+uint64(len(delta.data)) || addr == delta.addr-uint64(len(p)) {
			return delta, false
		}
	}
	return nil, false
}

// Update inserts a new read or write event into the log
func (m *MemLog) Update(addr uint64, p []byte, write bool) {
	var delta *memDelta
	var dup, before bool
	if delta, dup = m.Adjacent(addr, p, write); delta != nil {
		// adjacent to old memory delta
		if dup {
			return
		}
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
		delta = &memDelta{addr, nil, nil, write, ' '}
		m.log = append(m.log, delta)
	}
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
