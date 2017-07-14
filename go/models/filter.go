package models

type Filter interface {
	Filter(op Op) []Op
	Flush() []Op
}

// TODO move into loop file, same package
// LoopCollapse

//func (s *SubTree) Filter(op Op) []Op {}
//func (s *SubTree) Flush() []Op       {}
