package models

import (
	"github.com/lunixbochs/struc"
	"io"
)

type StrucStream struct {
	Stream  io.ReadWriter
	Options *struc.Options
}

func (s *StrucStream) Pack(i interface{}) error {
	return struc.PackWithOptions(s.Stream, i, s.Options)
}

func (s *StrucStream) Unpack(i interface{}) error {
	return struc.UnpackWithOptions(s.Stream, i, s.Options)
}
