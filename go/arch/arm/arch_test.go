package arm

import (
	"testing"
)

var testAsm = `
mov r1, 100
l1: subs r1, 1
    bge l1
`

func TestArm(t *testing.T)          { Arch.SmokeTest(t) }
func TestArmExec(t *testing.T)      { Arch.TestExec(t, testAsm) }
func BenchmarkArmRegs(b *testing.B) { Arch.BenchRegs(b) }
func BenchmarkArmExec(b *testing.B) { Arch.BenchExec(b, testAsm) }
