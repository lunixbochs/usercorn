package models

type Filter interface {
	Filter(op Op) []Op
	Flush() []Op
}
