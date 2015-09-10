package loader

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"../models"
)

func LoadFile(path string) (models.Loader, error) {
	p, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(bytes.NewReader(p))
}

func Load(r io.ReaderAt) (models.Loader, error) {
	if MatchElf(r) {
		return NewElfLoader(r)
	} else if MatchMachO(r) {
		return NewMachOLoader(r)
	} else if MatchCgc(r) {
		return NewCgcLoader(r)
	} else {
		return nil, errors.New("Could not identify file magic.")
	}
}
