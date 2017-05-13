package loader

import (
	"encoding/binary"
	"github.com/pkg/errors"
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
	if err != nil {
		return nil, errors.Wrap(err, "failed to open file")
	}
	stat, err := r.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "failed to stat file")
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
