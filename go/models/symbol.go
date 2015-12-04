package models

type Symbol struct {
	Name       string
	Start, End uint64
	Dynamic    bool
}

func (s Symbol) Contains(addr uint64) bool {
	return s.Start <= addr && (s.Start+s.End > addr || s.End == 0)
}
