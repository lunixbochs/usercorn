package loader

import (
	"encoding/binary"
	"io"
	"os"

	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type BpfLoader struct {
	LoaderBase
	codereader   io.ReaderAt
	codesize     int
	packetreader io.ReaderAt
	packetsize   int
}

func tryRead(filename string) (*os.File, int, error) {
	r, err := os.Open(filename)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to open file")
	}
	stat, err := r.Stat()
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to stat file")
	}
	size := stat.Size()

	if size == 0 {
		return nil, 0, errors.New("Cannot read from file")
	}

	return r, int(size), nil
}

func NewBpfLoader(filename, pcap string) (models.Loader, error) {
	codereader, codesize, err := tryRead(filename)
	if err != nil {
		return nil, errors.Wrap(err, "could not load filter")
	}

	packetreader, packetsize, err := tryRead(pcap)
	if err != nil {
		return nil, errors.Wrap(err, "could not load filter")
	}

	return &BpfLoader{
		LoaderBase: LoaderBase{
			arch:      "bpf",
			bits:      16,
			byteOrder: binary.LittleEndian,
			os:        "noos", // TODO: Should extensions be handled by an 'OS'?
			entry:     0x80000000,
		},
		codereader:   codereader,
		codesize:     codesize,
		packetreader: packetreader,
		packetsize:   packetsize,
	}, nil
}

func (r *BpfLoader) Segments() ([]models.SegmentData, error) {
	var segs []models.SegmentData

	// Code segment
	segs = append(segs, models.SegmentData{
		Off:  0,
		Addr: 0x80000000,
		Size: uint64(r.codesize),
		Prot: cpu.PROT_READ | cpu.PROT_EXEC,
		DataFunc: func() ([]byte, error) {
			p := make([]byte, r.codesize)
			n, err := r.codereader.ReadAt(p, 0)
			// Eat EOF error
			if err == io.EOF {
				err = nil
			}
			return p[:n], err
		},
	})

	// Packet segment
	segs = append(segs, models.SegmentData{
		Off:  0,
		Addr: 0,
		Size: uint64(r.packetsize),
		Prot: cpu.PROT_READ,
		DataFunc: func() ([]byte, error) {
			p := make([]byte, r.packetsize)
			n, err := r.packetreader.ReadAt(p, 0)
			// Eat EOF error
			if err == io.EOF {
				err = nil
			}
			return p[:n], err
		},
	})
	return segs, nil
}
