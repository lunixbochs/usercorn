package ndh

import (
	"encoding/hex"
	"testing"
)

var asmHex = "1b00000402003880040201000004020200000402050000040a02001702020a050a0011f2ff0401000404010101040202388004000305301c48656c6c6f20576f726c6420210a00"

func TestNdhDis(t *testing.T) {
	code, err := hex.DecodeString(asmHex)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&Dis{}).Dis(code, 0x8000)
	for _, ins := range out {
		t.Log(ins)
	}
	if err != nil {
		t.Fatal(err)
	}
}
