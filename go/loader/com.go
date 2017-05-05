package loader

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/lunixbochs/usercorn/go/models"
)

type ComLoader struct {
	LoaderBase
	Size int
	r    io.ReaderAt
}

func (c *ComLoader) OS() string {
	return "DOS"
}

func NewComLoader(filename string) (models.Loader, error) {
	r, err := os.Open(filename)
	stat, err := r.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()

	if size == 0 {
		return nil, errors.New("Cannot read from file")
	}
	return &ComLoader{
		LoaderBase: LoaderBase{
			arch:      "x86_16",
			bits:      16,
			byteOrder: binary.LittleEndian,
			os:        "dos",
			entry:     0x100,
		},
		Size: int(size),
		r:    r,
	}, nil
}

func (r *ComLoader) Segments() ([]models.SegmentData, error) {
	var segs []models.SegmentData

	// Completely flat memory model
	// TODO: Add PSP
	segs = append(segs, models.SegmentData{
		Off:  0,
		Addr: 0,
		Size: 0x100,
		Prot: 7,
		DataFunc: func() ([]byte, error) {
			// TODO: Use real PSP
			psp := make([]byte, 0x100)
			return psp, nil
		},
	})
	// Main segment
	segs = append(segs, models.SegmentData{
		Off:  0,
		Addr: 0x100,
		Size: uint64(r.Size),
		Prot: 7,
		DataFunc: func() ([]byte, error) {
			p := make([]byte, r.Size)
			n, err := r.r.ReadAt(p, 0)
			// Eat EOF error
			if err == io.EOF {
				err = nil
			}
			return p[:n], err
		},
	})
	return segs, nil
}
