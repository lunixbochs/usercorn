package models

import (
	"encoding/json"
	"io"
)

type Op interface {
	json.Marshaler

	Sizeof() int
	Pack([]byte)
	Unpack(r io.Reader) (int, error)
}
