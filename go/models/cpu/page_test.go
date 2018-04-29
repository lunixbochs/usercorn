package cpu

import (
	"testing"
)

func page_eq(a Pages, b Pages) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPageFind(t *testing.T) {
	mem := Pages{
		&Page{Addr: 0x1000, Size: 0x1000},
		&Page{Addr: 0x2000, Size: 0x1000},
		&Page{Addr: 0x4000, Size: 0x2000},
		&Page{Addr: 0x6000, Size: 0x2000},
	}
	if mem.Find(0x1000) != mem[0] ||
		mem.Find(0x1001) != mem[0] ||
		mem.Find(0x1fff) != mem[0] {
		t.Error("Find() failed")
	}
	if mem.Find(0x3000) != nil ||
		mem.Find(0x1) != nil ||
		mem.Find(0x10000) != nil {
		t.Error("Find() negative failed")
	}
	if !page_eq(mem.FindRange(0x0, 0x10000), mem) ||
		!page_eq(mem.FindRange(0x0, 0x1000), nil) ||
		!page_eq(mem.FindRange(0x1000, 0x1000), mem[:1]) ||
		!page_eq(mem.FindRange(0x1000, 0x2000), mem[:2]) ||
		!page_eq(mem.FindRange(0x2000, 0x2000), mem[1:2]) ||
		!page_eq(mem.FindRange(0x2000, 0x4000), mem[1:3]) ||
		!page_eq(mem.FindRange(0x2000, 0x10000), mem[1:]) {
		t.Error("FindRange() failed")
	}
}
