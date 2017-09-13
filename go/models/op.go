package models

import (
	"encoding/json"
	"io"
)

type Op interface {
	json.Marshaler

	Pack(w io.Writer) (int, error)
	Unpack(r io.Reader) (int, error)
}
