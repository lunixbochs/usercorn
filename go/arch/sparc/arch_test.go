package sparc

import (
	"testing"
)

var testAsm = `
set 100, %l0
loop: sub %l0, 1, %l0
      cmp %l0, 0
      bg loop
      nop
`

func TestSparc(t *testing.T)          { Arch.SmokeTest(t) }
func TestSparcExec(t *testing.T)      { Arch.TestExec(t, testAsm) }
func BenchmarkSparcRegs(b *testing.B) { Arch.BenchRegs(b) }
func BenchmarkSparcExec(b *testing.B) { Arch.BenchExec(b, testAsm) }
