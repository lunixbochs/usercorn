package models

import (
	"fmt"
	"strings"

	"github.com/mgutz/ansi"
)

type StatusDiff struct {
	U       Usercorn
	oldRegs map[int]uint64
}

var chSame = ansi.ColorCode("default:default")
var chNew = ansi.ColorCode("default+bu:default")

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
	Enum     int
	Name     string
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
					New:     s1[pos:i],
					Old:     s2[pos:i],
					Changed: !matching,
				})
				pos = i
			}
			matching = !matching
		}
	}
	if pos < len(s1) {
		masks = append(masks, ChangeMask{
			New:     s1[pos:len(s1)],
			Old:     s2[pos:len(s1)],
			Changed: !matching,
		})
	}
	return masks
}

func (c *Change) String(bsz int, color bool) string {
	var out []string
	hexFmt := fmt.Sprintf("%%0%dx", bsz)
	lineStart := fmt.Sprintf(" %4s 0x", c.Name)
	if c.Changed() {
		if color {
			out = append(out, fmt.Sprintf(" %s 0x", colorPad(c.Name, chNew, 4)))
			for _, mask := range c.Mask(bsz) {
				col := chSame
				if mask.Changed {
					col = chNew
				}
				out = append(out, col+mask.New)
			}
			out = append(out, ansi.Reset)
		} else {
			out = append(out, fmt.Sprintf("+ "+lineStart+hexFmt, c.New))
		}
	} else {
		out = append(out, fmt.Sprintf(lineStart+hexFmt, c.New))
	}
	return strings.Join(out, "")
}

type Changes struct {
	Bsz     int
	Changes []*Change
}

func (cs *Changes) String(color bool) string {
	var out []string
	var printRow = func(changes []*Change, cols int) {
		if len(changes) < cols && len(changes) > 0 {
			padLen := cs.Bsz + len(" regn 0x ")
			pad := strings.Repeat(" ", padLen*(cols-len(changes)))
			out = append(out, pad)
		}
		for _, c := range changes {
			out = append(out, c.String(cs.Bsz, color))
			out = append(out, " ")
		}
		if len(changes) > 0 {
			out = append(out, "\n")
		}
	}
	changes := cs.Changes
	// print column-wise output
	cols := 4
	rows := len(changes) / cols
	lastRow := changes[rows*cols:]
	row := make([]*Change, cols)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			row[j] = changes[j*rows+i]
		}
		printRow(row, cols)
	}
	if rows == 0 {
		cols = 0
	}
	printRow(lastRow, cols)
	return strings.Join(out, "")
}

func (cs *Changes) Changed() []*Change {
	ret := make([]*Change, 0, cs.Count())
	for _, c := range cs.Changes {
		if c.Changed() {
			ret = append(ret, c)
		}
	}
	return ret
}

func (cs *Changes) Count() int {
	ret := 0
	for _, c := range cs.Changes {
		if c.Changed() {
			ret += 1
		}
	}
	return ret
}

func (cs *Changes) Find(enum int) *Change {
	for _, c := range cs.Changes {
		if c.Enum == enum {
			return c
		}
	}
	return nil
}

func (s *StatusDiff) Changes(onlyChanged bool) *Changes {
	regs, _ := s.U.RegDump()
	cs := make([]*Change, 0, len(regs))
	for _, reg := range regs {
		if onlyChanged && !reg.Default {
			continue
		}
		var oldReg uint64
		if s.oldRegs != nil {
			oldReg = s.oldRegs[reg.Enum]
		}
		change := NewChange(reg.Name, reg.Val, oldReg)
		if !onlyChanged || change.Changed() {
			cs = append(cs, change)
		}
	}
	s.oldRegs = make(map[int]uint64, len(regs))
	for _, r := range regs {
		s.oldRegs[r.Enum] = r.Val
	}
	return &Changes{Bsz: int(s.U.Bits() / 4), Changes: cs}
}
