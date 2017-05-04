package models

import (
	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
	"io"
)

type StrucStream struct {
	Stream  io.ReadWriter
	Options *struc.Options
	Error   error
}

func NewStrucStream(f io.ReadWriter, opts *struc.Options) *StrucStream {
	return &StrucStream{Stream: f, Options: opts}
}

func (s *StrucStream) Pack(vals ...interface{}) error {
	if s.Error != nil {
		return s.Error
	}
	for _, val := range vals {
		if s.Error = struc.PackWithOptions(s.Stream, val, s.Options); s.Error != nil {
			s.Error = errors.Wrap(s.Error, "struc.PackWithOptions() failed")
			return s.Error
		}
	}
	return nil
}

func (s *StrucStream) Unpack(vals ...interface{}) error {
	if s.Error != nil {
		return s.Error
	}
	for _, val := range vals {
		if s.Error = struc.UnpackWithOptions(s.Stream, val, s.Options); s.Error != nil {
			s.Error = errors.Wrap(s.Error, "struc.UnpackWithOptions() failed")
			return s.Error
		}
	}
	return nil
}

func (s *StrucStream) Sizeof(vals ...interface{}) (int, error) {
	if s.Error != nil {
		return 0, s.Error
	}
	var n, size int
	for _, val := range vals {
		n, s.Error = struc.SizeofWithOptions(val, s.Options)
		if s.Error != nil {
			s.Error = errors.Wrap(s.Error, "struc.SizeofWithOptions() failed")
			return 0, s.Error
		}
		size += n
	}
	return size, nil
}
