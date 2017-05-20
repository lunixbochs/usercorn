package loader

import (
	"bytes"
	"encoding/binary"
	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

var ndhMagic = []byte{0x2e, 0x4e, 0x44, 0x48}

func MatchNdh(r io.ReaderAt) bool {
	var p [4]byte
	_, err := r.ReadAt(p[:], 0)
	return err == nil && bytes.Equal(p[:], ndhMagic)
}

type ndhHeader struct {
	Magic [4]byte
	Size  uint16
}

type NdhLoader struct {
	LoaderBase
	Text    []byte
	TextOff int
}

func unpackAt(r io.ReaderAt, i interface{}, at uint32) (int, error) {
	size, err := struc.Sizeof(i)
	if err != nil {
		return 0, err
	}
	return size, struc.UnpackWithOrder(io.NewSectionReader(r, int64(at), int64(size)), i, binary.LittleEndian)
}

func NewNdhLoader(r io.ReaderAt, arch string) (models.Loader, error) {
	var header ndhHeader
	off, err := unpackAt(r, &header, 0)
	if err != nil {
		return nil, err
	}
	text, err := ioutil.ReadAll(io.NewSectionReader(r, int64(off), int64(header.Size)))
	if err != nil {
		return nil, errors.Wrap(err, "io.ReadFull() failed")
	}
	return &NdhLoader{
		LoaderBase: LoaderBase{
			arch: "ndh",
			bits: 16,
			os:   "ndh",
			// TODO: vmndh supports aslr/PIE by shifting stack and .text
			entry:     uint64(0x8000),
			byteOrder: binary.LittleEndian,
		},
		Text:    text,
		TextOff: off,
	}, nil
}

func (n *NdhLoader) Segments() ([]models.SegmentData, error) {
	var segs []models.SegmentData
	segs = append(segs, models.SegmentData{
		Off: uint64(n.TextOff),
		// TODO: PIE?
		Addr: uint64(0x8000),
		// Add 4 bytes incase we need to read the very last instruction
		Size: uint64(len(n.Text)) + 4,
		// FIXME: assuming R-X
		Prot: cpu.PROT_READ | cpu.PROT_EXEC,
		DataFunc: func() ([]byte, error) {
			return n.Text, nil
		},
	})
	return segs, nil
}
