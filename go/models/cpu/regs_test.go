package cpu

import (
	"testing"
)

func makeRegs(bits uint) ([]int, *Regs) {
	enums := make([]int, 100)
	for i := range enums {
		enums[i] = 100 - i
	}
	return enums, NewRegs(bits, enums)
}

func BenchmarkRegsRead(b *testing.B) {
	enums, regs := makeRegs(64)
	for i := 0; i < b.N; i++ {
		regs.RegRead(enums[i%len(enums)])
	}
}

func BenchmarkRegsWrite(b *testing.B) {
	enums, regs := makeRegs(64)
	for i := 0; i < b.N; i++ {
		regs.RegWrite(enums[i%len(enums)], uint64(i))
	}
}

func TestRegs(t *testing.T) {
	enums, regs := makeRegs(64)

	// save context to check zeroes later
	ctx, err := regs.ContextSave(nil)
	if err != nil {
		t.Fatal(err, "initial ContextSave() failed")
	}

	// set all regs to pos * 2
	for i, e := range enums {
		if err := regs.RegWrite(e, uint64(i*2)); err != nil {
			t.Fatal(err, "initial RegWrite() failed")
		}
	}

	// check first set
	for i, e := range enums {
		if val, err := regs.RegRead(e); err != nil {
			t.Fatal(err, "initial RegRead() failed")
		} else if val != uint64(i*2) {
			t.Fatalf("RegRead() returned %d, expecting %d", val, i*2)
		}
	}

	// restore context and check
	if err := regs.ContextRestore(ctx); err != nil {
		t.Fatal(err, "ContextRestore() failed")
	}
	for _, e := range enums {
		if val, err := regs.RegRead(e); err != nil {
			t.Fatal(err, "RegRead() failed")
		} else if val != 0 {
			t.Fatalf("RegRead() returned %d, expecting 0", val)
		}
	}

	// test reusing context
	if err := regs.RegWrite(enums[0], 1); err != nil {
		t.Fatal(err, "RegWrite() failed")
	}
	if _, err := regs.ContextSave(ctx); err != nil {
		t.Fatal(err, "ContextSave() failed")
	}
	if err := regs.RegWrite(enums[0], 0); err != nil {
		t.Fatal(err, "RegWrite() failed")
	}
	if err := regs.ContextRestore(ctx); err != nil {
		t.Fatal(err, "ContextRestore() failed")
	}
	if val, err := regs.RegRead(enums[0]); err != nil {
		t.Fatal(err, "RegRead() failed")
	} else if val != 1 {
		t.Fatalf("RegRead() returned %d, expecting 1", val)
	}
}

func TestRegs8(t *testing.T) {
	enums, regs := makeRegs(8)
	if err := regs.RegWrite(enums[0], 0xffff); err != nil {
		t.Fatal("RegWrite() failed")
	}
	if val, err := regs.RegRead(enums[0]); err != nil {
		t.Fatal("RegRead() failed")
	} else if val != 0xffff&0xff {
		t.Fatalf("RegRead() returned %d, expecting 255", val)
	}
}
