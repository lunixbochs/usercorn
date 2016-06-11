package record

import (
	"bytes"
	"testing"
)

func TestOpFrame(t *testing.T) {
	var buf bytes.Buffer

	frame := &OpFrame{}
	frame.Ops = []Op{
		&OpMemMap{0x1000, 0x1000, 7},
		&OpMemWrite{0x1000, []byte{0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00}}, // mov rax, 1
		&OpExecAbs{0x1000, 0x7},
		&OpRegChange{35, 1}, // 35 is rax
	}

	if _, err := Pack(&buf, frame); err != nil {
		t.Fatal(err)
	}

	_, _, err := Unpack(&buf)
	if err != nil {
		t.Fatal(err)
	}
}
