package models

import (
	"encoding/binary"
	"github.com/lunixbochs/struc"
	"io"
)

type StrucStream struct {
	Stream io.ReadWriter
	Order  binary.ByteOrder
}

func (s *StrucStream) Pack(i interface{}) error {
	return struc.PackWithOrder(s.Stream, i, s.Order)
}

func (s *StrucStream) Unpack(i interface{}) error {
	return struc.UnpackWithOrder(s.Stream, i, s.Order)
}
