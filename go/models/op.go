package models

import "io"

type Op interface {
	Pack(w io.Writer) (int, error)
	Unpack(r io.Reader) (int, error)
}
