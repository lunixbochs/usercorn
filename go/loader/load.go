package loader

import (
	"bytes"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"

	"github.com/lunixbochs/usercorn/go/models"
)

var UnknownMagic = errors.New("Could not identify file magic.")

func LoadFile(path string) (models.Loader, error) {
	return LoadFileArch(path, "any")
}

func Load(r io.ReaderAt) (models.Loader, error) {
	return LoadArch(r, "any")
}

func LoadFileArch(path string, arch string) (models.Loader, error) {
	p, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadArch(bytes.NewReader(p), arch)
}

func LoadArch(r io.ReaderAt, arch string) (models.Loader, error) {
	if MatchElf(r) {
		return NewElfLoader(r, arch)
	} else if MatchMachO(r) {
		return NewMachOLoader(r, arch)
	} else if MatchCgc(r) {
		return NewCgcLoader(r, arch)
	} else if MatchNdh(r) {
		return NewNdhLoader(r, arch)
	} else {
		return nil, errors.WithStack(UnknownMagic)
	}
}
