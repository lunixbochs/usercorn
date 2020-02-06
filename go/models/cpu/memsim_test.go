package cpu

import (
	"bytes"
	"testing"
)

// this shouldn't repeat much at width
// usercorn needs a de bruijn sequence generator/searcher at some point
func pattern(len int) []byte {
	p := make([]byte, len)
	width := 8
	for i := range p {
		cycle := i / width
		p[i] = byte(cycle*width*i + i)
	}
	return p
}

// table of overlap tests for an 0x1100-0x1200 region
// {start, end, should_error}
var overlapTable = [][]uint64{
	{0x1000, 0x1100, 0},
	{0x1000, 0x1050, 0},
	{0x1000, 0x1200, 1},
	{0x1000, 0x1250, 1},
	{0x1100, 0x1150, 1},
	{0x1100, 0x1200, 1},
	{0x1100, 0x1250, 1},
	{0x1150, 0x1200, 1},
	{0x1150, 0x1250, 1},
	{0x1200, 0x1250, 0},
}

func BenchmarkMemSimMap(b *testing.B) {
	m := &MemSim{}
	for i := 0; i < b.N; i++ {
		addr := uint64(i*0x1000) & 0xffffffff
		m.Map(addr, 0x1000, 0, true)
	}
}

func BenchmarkMemSimRead(b *testing.B) {
	m := &MemSim{}
	m.Map(0x1000, 0x100000, 0, true)
	p := make([]byte, 4)
	for i := 0; i < b.N; i++ {
		m.Read(uint64(i*4)&0xfffff, p, 0)
	}
}

func BenchmarkMemSimWrite(b *testing.B) {
	m := &MemSim{}
	m.Map(0x1000, 0x100000, 0, true)
	p := make([]byte, 4)
	for i := 0; i < b.N; i++ {
		m.Write(uint64(i*4)&0xfffff, p, 0)
	}
}

func TestMemSim(t *testing.T) {
	m := &MemSim{}
	m.Map(0x1000, 0x1000, 0, false)

	// basic read/write test
	b := pattern(0x1000)
	c := make([]byte, len(b))
	if err := m.Write(0x1000, b, 0); err != nil {
		t.Fatal(err, "write failed")
	} else if err := m.Read(0x1000, c, 0); err != nil {
		t.Fatal(err, "read failed")
	} else if !bytes.Equal(b, c) {
		t.Fatal("read/write inconsistent")
	}

	// make sure still-mapped region reads/writes correctly
	for _, region := range overlapTable {
		p := make([]byte, region[1]-region[0])
		if err := m.Read(region[0], p, 0); err != nil {
			t.Errorf("read_mapped(%#x, %#x) error: %v", region[0], region[1], err)
		}
		if err := m.Write(region[0], p, 0); err != nil {
			t.Errorf("write_mapped(%#x, %#x) error: %v", region[0], region[1], err)
		}
	}

	// unmaps 0x1100-0x1200
	m.Unmap(0x1100, 0x100)

	// make sure areas around unmapped region still have the right values
	if err := m.Read(0x1000, c[:0x100], 0); err != nil {
		t.Error("failed to read left-adjacent memory after unmap")
	} else if !bytes.Equal(b[:0x100], c[:0x100]) {
		t.Error("left-adjacent memory corruption after unmap")
	}
	if err := m.Read(0x1200, c[:0x100], 0); err != nil {
		t.Error("failed to read right-adjacent memory after unmap")
	} else if !bytes.Equal(b[0x200:0x300], c[:0x100]) {
		t.Error("right-adjacent memory corruption after unmap")
	}

	// make sure unmapped region reads/writes fail correctly
	for _, region := range overlapTable {
		p := make([]byte, region[1]-region[0])
		if err := m.Read(region[0], p, 0); err == nil && region[2] == 1 || err != nil && region[2] == 0 {
			t.Errorf("read_unmapped(%#x, %#x) bad error value: %v", region[0], region[1], err)
		}
		if err := m.Write(region[0], p, 0); err == nil && region[2] == 1 || err != nil && region[2] == 0 {
			t.Errorf("write_unmapped(%#x, %#x) bad error value: %v", region[0], region[1], err)
		}
	}

	// test io across multiple adjacent maps
	m = &MemSim{}
	m.Map(0x1000, 0x1000, 0, false)
	m.Map(0x2000, 0x1000, 0, false)
	m.Map(0x3000, 0x1000, 0, false)

	b = pattern(0x3000)
	c = make([]byte, len(b))

	if err := m.Write(0x1000, b, 0); err != nil {
		t.Error(err, "while writing multiple adjacent maps")
	} else if err := m.Read(0x1000, c, 0); err != nil {
		t.Error(err, "while reading multiple adjacent maps")
	} else if !bytes.Equal(b, c) {
		t.Log(b)
		t.Log(c)
		t.Error("memory corruption when reading multiple adjacent maps")
	}

	// setup for overlapping map tests
	m = &MemSim{}
	b = pattern(0x10000)
	c = make([]byte, len(b))

	m.Map(0x1000, 0x10000, 0, false)
	if err := m.Write(0x1000, b, 0); err != nil {
		t.Error(err, "while writing initial zeroing map")
	} else if err := m.Read(0x1000, c, 0); err != nil {
		t.Error(err, "while reading initial zeroing map")
	} else if !bytes.Equal(b, c) {
		t.Error("corruption while reading initial zeroing map")
	}

	// test overlapping Map() with zero=false
	m.Map(0x1000, 0x10000, 0, false)
	c = make([]byte, len(b))
	if err := m.Read(0x1000, c, 0); err != nil {
		t.Error(err, "while reading zeroing map")
	} else if !bytes.Equal(b, c) {
		t.Error("memory inconsistent when remapping with zero=false")
	}

	// test overlapping Map() with zero=true (reusing the last map)
	m.Map(0x2000, 0x1000, 0, true)
	// this zeroes the equivalent page in b
	copy(b[0x1000:0x2000], make([]byte, 0x1000))

	c = make([]byte, len(b))
	if err := m.Read(0x1000, c, 0); err != nil {
		t.Error(err, "while reading zeroing map")
	} else if !bytes.Equal(b, c) {
		t.Error("memory inconsistent when remapping with zero=true")
	}
	// TODO: test Prot() enforcement, and prot behavior for overlapping maps
}

func TestMemMirror(t *testing.T) {
	m := &MemSim{}
	m.Map(0x1000, 0x1000, 7, false)

	if err := m.Write(0x1000, []byte{1, 2, 3}, 7); err != nil {
		t.Error(err, "while writing initial map")
	}
	p3 := make([]byte, 3)
	if err := m.Read(0x1000, p3, 7); err != nil {
		t.Error(err, "while reading initial map")
	}
	if !bytes.Equal(p3, []byte{1, 2, 3}) {
		t.Error("initial map read/write mismatch")
	}
	if err := m.Read(0x10000, p3, 7); err == nil {
		t.Error("mirror region is readable before test")
	}
	m.Mirror(0x10000, 0x1000, 7, 0x1000)
	if err := m.Read(0x10000, p3, 7); err != nil {
		t.Error(err, "while reading mirror")
	}
	if !bytes.Equal(p3, []byte{1, 2, 3}) {
		t.Error("map write -> mirror read mismatch")
	}

	if err := m.Write(0x10000, []byte{4, 5, 6}, 7); err != nil {
		t.Error(err, "while writing mirror")
	}
	if err := m.Read(0x10000, p3, 7); err != nil {
		t.Error(err, "while reading mirror")
	}
	if !bytes.Equal(p3, []byte{4, 5, 6}) {
		t.Error("mirror write/read mismatch")
	}
	p3 = []byte{0, 0, 0}
	if err := m.Read(0x1000, p3, 7); err != nil {
		t.Error(err, "while reading map")
	}
	if !bytes.Equal(p3, []byte{4, 5, 6}) {
		t.Error("mirror write/map read mismatch")
	}
}
