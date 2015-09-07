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

func colorPad(s, color string, pad int) string {
	length := len(s)
	s = color + s + ansi.Reset
	if length < pad {
		s = strings.Repeat(" ", pad-length) + s
	}
	return s
}

type ChangeMask struct {
	Old, New string
	Changed  bool
}

type Change struct {
	Old, New uint64
	Name     string
}

type Changes struct {
	Bsz     int
	Changes []*Change
}

func NewChange(name string, val, oldVal uint64) *Change {
	return &Change{
		Old:  oldVal,
		New:  val,
		Name: name,
	}
}

func (c *Change) Changed() bool {
	return c.Old != c.New
}

func (c *Change) Mask(bsz int) []ChangeMask {
	hexFmt := fmt.Sprintf("%%0%dx", bsz)
	s1, s2 := fmt.Sprintf(hexFmt, c.New), fmt.Sprintf(hexFmt, c.Old)
	pos := 0
	matching := true
	masks := make([]ChangeMask, 0, len(s1))
	for i := range s1 {
		if (s1[i] == s2[i]) != matching {
			if i > pos {
				masks = append(masks, ChangeMask{
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
		masks = append(masks, ChangeMask{
			Old:     s1[pos:len(s1)],
			New:     s2[pos:len(s1)],
			Changed: !matching,
		})
	}
	return masks
}

func (c *Change) Print(bsz int, color bool) {
	hexFmt := fmt.Sprintf("%%0%dx", bsz)
	lineStart := fmt.Sprintf(" %4s 0x", c.Name)
	if c.Changed() {
		if color {
			fmt.Fprintf(os.Stderr, " %s 0x", colorPad(c.Name, chNew, 4))
			for _, mask := range c.Mask(bsz) {
				col := chSame
				if mask.Changed {
					col = chNew
				}
				fmt.Fprintf(os.Stderr, col+mask.New)
			}
			fmt.Fprintf(os.Stderr, ansi.Reset)
		} else {
			fmt.Fprintf(os.Stderr, "+ "+lineStart+hexFmt, c.New)
		}
	} else {
		fmt.Fprintf(os.Stderr, lineStart+hexFmt, c.New)
	}
}

func (cs *Changes) Print(color, onlyChanged bool) {
	i := 0
	for _, c := range cs.Changes {
		if c.Changed() || !onlyChanged {
			i++
			if i > 0 && i%3 == 0 {
				fmt.Fprintln(os.Stderr)
			}
			fmt.Fprintf(os.Stderr, " ")
			c.Print(cs.Bsz, color)
		}
	}
	if i > 0 {
		fmt.Fprintln(os.Stderr)
	}
}

func (s *StatusDiff) Changes() *Changes {
	regs, _ := s.U.RegDump()
	cs := make([]*Change, 0, len(regs))
	for name, val := range regs {
		oldVal, _ := s.oldRegs[name]
		cs = append(cs, NewChange(name, val, oldVal))
	}
	s.oldRegs = regs
	return &Changes{Bsz: int(s.U.Bits() / 4), Changes: cs}
}
