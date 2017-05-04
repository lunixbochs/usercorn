package loader

import (
	"encoding/binary"

	"github.com/lunixbochs/usercorn/go/models"
)

type NullLoader struct {
	LoaderBase
}

func NewNullLoader(arch, os string, byteOrder binary.ByteOrder, entry uint64) models.Loader {
	return &NullLoader{LoaderBase{
		arch:      arch,
		os:        os,
		byteOrder: byteOrder,
		entry:     entry,
	}}
}
