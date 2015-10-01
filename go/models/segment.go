package models

type SegmentData struct {
	Off        uint64
	Addr, Size uint64
	DataFunc   func() ([]byte, error)
}

func (s *SegmentData) Data() ([]byte, error) {
	return s.DataFunc()
}

func (s *SegmentData) ContainsPhys(addr uint64) bool {
	return s.Off <= addr && addr < s.Off+s.Size
}

func (s *SegmentData) ContainsVirt(addr uint64) bool {
	return s.Addr <= addr && addr < s.Addr+s.Size
}

type Segment struct {
	Start, End uint64
}

func (s *Segment) Overlaps(o *Segment) bool {
	return (s.Start >= o.Start && s.Start < o.End) || (o.Start >= s.Start && o.Start < s.End)
}

func (s *Segment) Merge(o *Segment) {
	if s.Start > o.Start {
		s.Start = o.Start
	}
	if s.End < o.End {
		s.End = o.End
	}
}
