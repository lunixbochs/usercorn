package models

import (
	"fmt"
	"os"
	"strings"

	"github.com/mgutz/ansi"
)

type StatusDiff struct {
	U       Usercorn
	Color   bool
	oldRegs map[string]uint64
}

var chSame = ansi.ColorCode("black:default")
var chNew = ansi.ColorCode("black+bu:default")

type change struct {
	Old     string
	New     string
	Changed bool
}

func splitChanges(val, oldVal uint64, hexFmt string) []change {
	s1, s2 := fmt.Sprintf(hexFmt, val), fmt.Sprintf(hexFmt, oldVal)
	pos := 0
	matching := true
	changes := make([]change, 0, len(s1))
	for i := range s1 {
		if (s1[i] == s2[i]) != matching {
			if i > pos {
				changes = append(changes, change{
					Old:     s1[pos:i],
					New:     s2[pos:i],
					Changed: !matching,
				})
				pos = i
			}
			matching = !matching
		}
	}
	if pos < len(s1) {
		changes = append(changes, change{
			Old:     s1[pos:len(s1)],
			New:     s2[pos:len(s1)],
			Changed: !matching,
		})
	}
	return changes
}

func colorPad(s, color string, pad int) string {
	length := len(s)
	s = color + s + ansi.Reset
	if length < pad {
		s = strings.Repeat(" ", pad-length) + s
	}
	return s
}

func (s *StatusDiff) PrintReg(name string, val, oldVal uint64) {
	bsz := s.U.Bits() / 4
	hexFmt := fmt.Sprintf("%%0%dx", bsz)
	lineStart := fmt.Sprintf(" %4s 0x", name)
	if val != oldVal {
		if s.Color {
			fmt.Fprintf(os.Stderr, " %s 0x", colorPad(name, chNew, 4))
			for _, change := range splitChanges(val, oldVal, hexFmt) {
				col := chSame
				if change.Changed {
					col = chNew
				}
				fmt.Fprintf(os.Stderr, col+change.New)
			}
			fmt.Fprintf(os.Stderr, ansi.Reset)
		} else {
			fmt.Fprintf(os.Stderr, "+ "+lineStart+hexFmt, val)
		}
	} else {
		fmt.Fprintf(os.Stderr, lineStart+hexFmt, val)
	}
}

func (s *StatusDiff) Print(onlyChanged bool) {
	regs, _ := s.U.RegDump()
	i := 0
	for name, val := range regs {
		oldVal, _ := s.oldRegs[name]
		if onlyChanged && val == oldVal {
			continue
		}
		if i > 0 && i%3 == 0 {
			fmt.Fprintln(os.Stderr)
		}
		i++
		fmt.Fprintf(os.Stderr, " ")
		s.PrintReg(name, val, oldVal)
	}
	fmt.Fprintln(os.Stderr)
	s.oldRegs = regs
}
