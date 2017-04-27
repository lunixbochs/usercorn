package models

import (
	"debug/dwarf"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type SourceLine struct {
	dwarf.LineEntry
	Start  uint64
	End    uint64
	Source string
}

func (s *SourceLine) Contains(addr uint64) bool {
	return s.Start <= addr && s.End > addr
}

type DebugFile struct {
	Symbols   []Symbol
	DWARF     *dwarf.Data
	SourceMap []*SourceLine
	SymbolMap map[string]Symbol
}

type symByStart []Symbol
type srcByStart []*SourceLine

func (a symByStart) Len() int      { return len(a) }
func (a symByStart) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a symByStart) Less(i, j int) bool {
	return a[i].Start < a[j].Start || a[i].Start == a[j].Start && a[i].End < a[j].End
}
func (a srcByStart) Len() int      { return len(a) }
func (a srcByStart) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a srcByStart) Less(i, j int) bool {
	return a[i].Start < a[j].Start || a[i].Start == a[j].Start && a[i].End < a[j].End
}

// sorts symbols by starting addr for binary search during symbolication
// builds source and symbol maps
func (m *DebugFile) CacheSym() {
	m.SymbolMap = make(map[string]Symbol)
	for _, sym := range m.Symbols {
		m.SymbolMap[sym.Name] = sym
	}
	sort.Sort(symByStart(m.Symbols))
}

func (m *DebugFile) CacheSource(srcPaths []string) {
	m.SourceMap = m.buildSourceMap(srcPaths)
	sort.Sort(srcByStart(m.SourceMap))
}

func findFile(srcPaths []string, parent string, shortname string, fullname string) []string {
	// TODO: if path is absolute, try -prefix
	// TODO: relative path to the exectuable?
	basename := path.Base(shortname)
	parname := path.Join(parent, shortname)
	names := []string{shortname, fullname, basename, parname}
	candidates := names
	for _, src := range srcPaths {
		for _, end := range names {
			candidates = append(candidates, filepath.Join(src, end))
		}
	}
	for _, fname := range candidates {
		if _, err := os.Stat(fname); err == nil {
			if data, err := ioutil.ReadFile(fname); err == nil {
				return strings.Split(string(data), "\n")
			}
		}
	}
	return nil
}

func (m *DebugFile) buildSourceMap(srcPaths []string) []*SourceLine {
	var lines []*SourceLine
	if m.DWARF == nil {
		return nil
	}
	reader := m.DWARF.Reader()
	var compdirs []string
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag == dwarf.TagCompileUnit {
			compdirs = append(compdirs, entry.AttrField(dwarf.AttrCompDir).Val.(string))
		}
	}
	var common string
	if len(compdirs) > 0 {
		common = path.Clean(compdirs[0])
		for _, dir := range compdirs[1:] {
			dir = path.Clean(dir)
			for i := 0; i < len(dir) && i < len(common); i++ {
				if common[i] != dir[i] {
					common = common[:i]
					break
				}
			}
		}
		common = path.Dir(common)
	}

	reader.Seek(0)
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag == dwarf.TagCompileUnit {
			files := make(map[string][]string)
			if reader, err := m.DWARF.LineReader(entry); err == nil {
				var line dwarf.LineEntry
				var sl *SourceLine
				for {
					err := reader.Next(&line)
					if err != nil {
						break
					}
					source := ""
					shortname := line.File.Name
					fullname := line.File.Name
					if tmp, err := filepath.Rel(common, fullname); err == nil {
						shortname = tmp
					}
					var file []string
					var ok bool
					if file, ok = files[fullname]; !ok {
						file = findFile(srcPaths, path.Base(common), shortname, fullname)
						files[fullname] = file
					}
					if len(file) > 0 && line.Line-1 < len(file) {
						source = file[line.Line-1]
					}
					if sl != nil {
						sl.End = line.Address + 1
					}
					if line.EndSequence {
						break
					}
					sl = &SourceLine{
						LineEntry: line,
						Start:     line.Address,
						End:       line.Address + 1,
						Source:    strings.Replace(source, "\t", "    ", -1),
					}
					lines = append(lines, sl)
				}
			}
		}
		reader.SkipChildren()
	}
	return lines
}

// binary search on m.Symbols
func (m *DebugFile) Symbolicate(addr uint64) (result Symbol, distance uint64) {
	l := 0
	r := len(m.Symbols) - 1
	for l <= r {
		mid := (l + r) / 2
		e := m.Symbols[mid]
		if addr >= e.End {
			l = mid + 1
		} else if addr < e.Start {
			r = mid - 1
		} else {
			return e, addr - e.Start
		}
	}
	return
}

func (m *DebugFile) SymbolLookup(name string) Symbol {
	if s, ok := m.SymbolMap[name]; ok {
		return s
	}
	return Symbol{}
}

// performs a binary search on m.SourceMap for addr
func (m *DebugFile) FileLine(addr uint64) *SourceLine {
	l := 0
	r := len(m.SourceMap) - 1
	for l <= r {
		mid := (l + r) / 2
		e := m.SourceMap[mid]
		if addr >= e.End {
			l = mid + 1
		} else if addr < e.Start {
			r = mid - 1
		} else {
			return e
		}
	}
	return nil
}
