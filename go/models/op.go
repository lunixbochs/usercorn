package models

import "io"

type Op interface {
	Pack(w io.Writer) (int, error)
	Unpack(r io.Reader) (int, error)
}

type NoOp struct {
}

func (n *NoOp) Pack(w io.Writer) (int, error)   { return 0, nil }
func (n *NoOp) Unpack(r io.Reader) (int, error) { return 0, nil }
