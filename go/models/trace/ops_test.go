package trace

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lunixbochs/usercorn/go/models"
)

// these OPs are ordered to be semi-valid, so not by number
var allButSyscall = []models.Op{
	&OpNop{},
	&OpMemMap{0x1000, 0x1000, 7, 0, 0, "", ""},
	&OpMemMap{0x1000, 0x1000, 7, 1234, 0, "desc", "filename"},
	&OpMemProt{0x1000, 0x1000, 0},
	&OpMemProt{0x1000, 0x1000, 7},
	&OpMemWrite{0x1000, []byte{0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00}}, // mov rax, 1
	&OpJmp{0x1000, 0x7},
	&OpStep{0x7},
	&OpReg{35, 1}, // 35 is rax
	// no SpReg support higher in the stack yet, so this is bogus
	&OpSpReg{0xff, []byte{1, 2, 3, 4}},
	&OpMemRead{0x1000, 1},
	&OpMemUnmap{0x1000, 0x1000},
	&OpExit{},
}

var testSyscall = &OpSyscall{
	Num:  1,
	Ret:  2,
	Args: []uint64{1, 2, 3, 4, 5, 6, 7, 8},
	Ops:  allButSyscall,
}

var allUnframed = append(allButSyscall, testSyscall)

var testFrame = &OpFrame{Ops: allUnframed}
var testKeyframe = &OpKeyframe{Ops: allUnframed}

func TestOpFrame(t *testing.T) {
	buf := make([]byte, testFrame.Sizeof())
	testFrame.Pack(buf)
	op, _, err := Unpack(bytes.NewReader(buf), false)
	if err != nil {
		t.Fatal(err)
	}

	buf2 := make([]byte, op.Sizeof())
	op.Pack(buf2)
	_, _, err = Unpack(bytes.NewReader(buf2), false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, buf2) {
		t.Error("encoded forms differ")
	}
}

func BenchmarkPack(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tmp := make([]byte, testFrame.Sizeof())
		testFrame.Pack(tmp)
	}
}

func BenchmarkUnpack(b *testing.B) {
	tmp := make([]byte, testFrame.Sizeof())
	testFrame.Pack(tmp)
	r := bytes.NewReader(tmp)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		if _, _, err := Unpack(r, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJsonPack(b *testing.B) {
	_, err := json.Marshal(testFrame)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testFrame.MarshalJSON()
	}
}

func BenchmarkJsonUnpack(b *testing.B) {
	s, err := json.Marshal(testFrame)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dict := make(map[string]interface{})
		if err := json.Unmarshal(s, &dict); err != nil {
			b.Fatal(err)
		}
	}
}
