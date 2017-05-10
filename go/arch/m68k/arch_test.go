package m68k

import (
	"testing"
)

var testAsm = `
move.w #100, d1
loop: subq.w #1, d1
      cmpq.w #0, d1
      bra loop
`

func TestM68k(t *testing.T)          { Arch.SmokeTest(t) }
func BenchmarkM68kRegs(b *testing.B) { Arch.BenchRegs(b) }

// keystone can't assemble m68k
// func TestM68kExec(t *testing.T)      { Arch.TestExec(t, testAsm) }
// func BenchmarkM68kExec(b *testing.B) { Arch.BenchExec(b, testAsm) }
