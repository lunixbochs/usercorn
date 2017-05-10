package x86

import (
	"testing"
)

var testAsm = `
mov eax, 100
l1:
dec eax
cmp eax, 0
jg l1
`

func TestX86(t *testing.T)          { Arch.SmokeTest(t) }
func TestX86Exec(t *testing.T)      { Arch.TestExec(t, testAsm) }
func BenchmarkX86Regs(b *testing.B) { Arch.BenchRegs(b) }
func BenchmarkX86Exec(b *testing.B) { Arch.BenchExec(b, testAsm) }
