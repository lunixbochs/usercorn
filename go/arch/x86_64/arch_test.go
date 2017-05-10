package x86_64

import (
	"testing"
)

var testAsm = `
mov rax, 100
l1:
dec rax
cmp rax, 0
jg l1
`

func TestX86_64(t *testing.T)          { Arch.SmokeTest(t) }
func TestX86_64Exec(t *testing.T)      { Arch.TestExec(t, testAsm) }
func BenchmarkX86_64Regs(b *testing.B) { Arch.BenchRegs(b) }
func BenchmarkX86_64Exec(b *testing.B) { Arch.BenchExec(b, testAsm) }
