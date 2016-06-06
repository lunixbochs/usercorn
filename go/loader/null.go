package loader

import (
	"debug/dwarf"
	"encoding/binary"

	"github.com/lunixbochs/usercorn/go/models"
)

type NullLoader struct {
	LoaderHeader
}

func (n *NullLoader) DWARF() (*dwarf.Data, error) {
	return nil, nil
}

func (n *NullLoader) DataSegment() (uint64, uint64) {
	return 0, 0
}

func (n *NullLoader) Header() (uint64, []byte, int) {
	return 0, nil, 0
}

func (n *NullLoader) Interp() string {
	return ""
}

func (n *NullLoader) Segments() ([]models.SegmentData, error) {
	return nil, nil
}

func (n *NullLoader) Symbols() ([]models.Symbol, error) {
	return nil, nil
}

func (n *NullLoader) Type() int {
	return EXEC
}

func NewNullLoader(arch, os string, byteOrder binary.ByteOrder, entry uint64) models.Loader {
	return &NullLoader{LoaderHeader{
		arch:      arch,
		os:        os,
		byteOrder: byteOrder,
		entry:     entry,
	}}
}
