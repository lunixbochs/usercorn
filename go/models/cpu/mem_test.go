package cpu

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var asdf = []byte("asdf")

func TestMem8(t *testing.T) {
	mem := NewMem(8, binary.LittleEndian)
	if err := mem.MemMapProt(0x10, 0x10, 0); err != nil {
		t.Fatal("failed to map memory:", err)
	}
	if err := mem.MemMapProt(0x0, 0x1000, 0); err == nil {
		t.Fatal("mapped memory outside range")
	}
	if err := mem.MemMapProt(0x1000, 0x1000, 0); err == nil {
		t.Fatal("mapped memory outside range")
	}
	if err := mem.MemWrite(0x1000, asdf); err == nil {
		t.Error("write succeeded above mapped memory")
	}
}

func TestMem(t *testing.T) {
	mappings := [][]uint64{
		{0x1000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC},
		{0x2000, 0x1000, PROT_READ},
		{0x3000, 0x1000, PROT_READ | PROT_WRITE},
		{0x4000, 0x1000, PROT_READ | PROT_EXEC},
		{0x5000, 0x1000, PROT_EXEC},
	}

	mem := NewMem(16, binary.LittleEndian)
	for _, v := range mappings {
		if err := mem.MemMapProt(v[0], v[1], int(v[2])); err != nil {
			t.Fatalf("failed to map memory (%#x, %#x, %d): %v", v[0], v[1], v[2], err)
		}
	}
	// write outside bounds
	if err := mem.MemWrite(0, asdf); err == nil {
		t.Error("write succeeded below mapped memory")
	}
	if err := mem.MemWrite(0x6000, asdf); err == nil {
		t.Error("write succeeded above mapped memory")
	}
	// write inside bounds
	for _, v := range mappings {
		if err := mem.MemWrite(v[0], asdf); err != nil {
			t.Error("write failed inside mapped memory")
		}
	}
	// try to read our asdf from each mapping
	for _, v := range mappings {
		if tmp, err := mem.MemRead(v[0], uint64(len(asdf))); err != nil {
			t.Error("read failed inside mapped memory")
		} else if !bytes.Equal(tmp, asdf) {
			t.Error("read returned bad value")
		}
	}
	// now test memory protections
	tmp := make([]byte, 0x1000)
	for _, v := range mappings {
		if _, err := mem.ReadProt(v[0], v[1], int(v[2])); err != nil {
			t.Errorf("valid read failed on (%#x, %#x, %d): %v", v[0], v[1], v[2], err)
		}
		if _, err := mem.ReadProt(v[0], v[1], 8); err == nil {
			t.Errorf("invalid read succeeded on (%#x, %#x, %d)", v[0], v[1], v[2])
		}
		if err := mem.WriteProt(v[0], tmp, int(v[2])); err != nil {
			t.Errorf("valid write failed on (%#x, %#x, %d): %v", v[0], v[1], v[2], err)
		}
		if err := mem.WriteProt(v[0], tmp, 8); err == nil {
			t.Errorf("invalid write succeeded on (%#x, %#x, %d)", v[0], v[1], v[2])
		}
	}
	// test PROT_EXEC
	for _, v := range mappings {
		if _, err := mem.ReadProt(v[0], v[1], PROT_EXEC); (v[2]&PROT_EXEC == 0 && err == nil) || (v[2]&PROT_EXEC == PROT_EXEC && err != nil) {
			t.Error("PROT_EXEC mismatch")
		}
	}
}

func TestMemUint(t *testing.T) {
	rawtest := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ltable := map[int]uint64{
		1: 0x1,
		2: 0x0201,
		4: 0x04030201,
		8: 0x0807060504030201,
	}
	btable := map[int]uint64{
		1: 0x1,
		2: 0x0102,
		4: 0x01020304,
		8: 0x0102030405060708,
	}

	meml := NewMem(32, binary.LittleEndian)
	memb := NewMem(32, binary.BigEndian)

	if err := meml.MemMapProt(0x1000, 0x1000, PROT_READ|PROT_WRITE); err != nil {
		t.Fatal("failed to map memory:", err)
	}
	if err := memb.MemMapProt(0x1000, 0x1000, PROT_READ|PROT_WRITE); err != nil {
		t.Fatal("failed to map memory:", err)
	}
	if err := meml.MemWrite(0x1000, rawtest); err != nil {
		t.Error("failed to write memory:", err)
	}
	if err := memb.MemWrite(0x1000, rawtest); err != nil {
		t.Error("failed to write memory:", err)
	}
	// test reading canned values
	for size, val := range ltable {
		if n, err := meml.ReadUint(0x1000, size, PROT_READ); err != nil {
			t.Error("failed to read uint:", err)
		} else if n != val {
			t.Error("inconsistent uint value:", n, val)
		}
	}
	for size, val := range btable {
		if n, err := memb.ReadUint(0x1000, size, PROT_READ); err != nil {
			t.Error("failed to read uint:", err)
		} else if n != val {
			t.Error("inconsistent uint value:", n, val)
		}
	}
	// test writing, then reading canned values
	for size, val := range ltable {
		if err := meml.WriteUint(0x1000, size, PROT_WRITE, val); err != nil {
			t.Error("failed to write uint:", err)
		}
		if n, err := meml.ReadUint(0x1000, size, PROT_READ); err != nil {
			t.Error("failed to read uint:", err)
		} else if n != val {
			t.Error("inconsistent uint value:", n, val)
		}
	}
	for size, val := range btable {
		if err := memb.WriteUint(0x1000, size, PROT_WRITE, val); err != nil {
			t.Error("failed to write uint:", err)
		}
		if n, err := memb.ReadUint(0x1000, size, PROT_READ); err != nil {
			t.Error("failed to read uint:", err)
		} else if n != val {
			t.Error("inconsistent uint value:", n, val)
		}
	}
}
