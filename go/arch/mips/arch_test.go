package mips

import (
	"testing"
)

var testAsm = `
li $t0, 100
l1:
addi $t0, $t0, -1
bgt $t0, 0, l1
`

func TestMips(t *testing.T)          { Arch.SmokeTest(t) }
func TestMipsExec(t *testing.T)      { Arch.TestExec(t, testAsm) }
func BenchmarkMipsRegs(b *testing.B) { Arch.BenchRegs(b) }
func BenchmarkMipsExec(b *testing.B) { Arch.BenchExec(b, testAsm) }
