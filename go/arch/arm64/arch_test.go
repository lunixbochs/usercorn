package arm64

import (
	"testing"
)

var testAsm = `
mov x1, 100
l1:
subs x1, x1, 1
bge l1
`

func TestArm64(t *testing.T)          { Arch.SmokeTest(t) }
func TestArm64Exec(t *testing.T)      { Arch.TestExec(t, testAsm) }
func BenchmarkArm64Regs(b *testing.B) { Arch.BenchRegs(b) }
func BenchmarkArm64Exec(b *testing.B) { Arch.BenchExec(b, testAsm) }
