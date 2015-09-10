package models

type SegmentData struct {
	Addr uint64
	Data []byte
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
