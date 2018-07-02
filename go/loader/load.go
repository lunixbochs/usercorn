package loader

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
)

var UnknownMagic = errors.New("Could not identify file magic.")

func LoadFile(path string) (models.Loader, error) {
	return LoadFileArch(path, "any", NoOSHint)
}

func Load(r io.ReaderAt) (models.Loader, error) {
	return LoadArch(r, "any", NoOSHint)
}

func LoadFileArch(path string, arch, osHint string) (models.Loader, error) {
	p, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadArch(bytes.NewReader(p), arch, osHint)
}

func LoadArch(r io.ReaderAt, arch string, osHint string) (models.Loader, error) {
	if MatchElf(r) {
		return NewElfLoader(r, arch, osHint)
	} else if MatchMachO(r) {
		return NewMachOLoader(r, arch)
	} else if MatchCgc(r) {
		return NewCgcLoader(r, arch)
	} else {
		return nil, errors.WithStack(UnknownMagic)
	}
}
