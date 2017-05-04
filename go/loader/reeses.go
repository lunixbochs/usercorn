package loader

import (
	"bytes"
	"encoding/binary"
	"github.com/lunixbochs/struc"
	"io"

	"github.com/lunixbochs/usercorn/go/models"
)

func MatchReeses(r io.ReaderAt) bool {
	var p [4]byte
	_, err := r.ReadAt(p[:], 0)
	return err == nil && bytes.Equal(p[:], []byte{0x41, 0x4a, 0x5c, 0x62})
}

type reesesHeader struct {
	Magic         [4]byte
	Pad           [8]byte
	OffLoadSec    uint32
	OffReg        uint32
	NumLoad       uint16
	NumReg        uint16
	OffHash       uint32
	FakeStartAddr uint32
}

type reesesLoad struct {
	Addr   uint32
	Pad    uint32
	Length uint32
	Offset uint32
	Pad2   uint32
}

type ReesesReg struct {
	Num uint32
	Val uint32
}

type ReesesLoader struct {
	LoaderBase
	Hash  []byte
	Regs  []ReesesReg
	Loads []reesesLoad
	r     io.ReaderAt
}

func unpackAt(r io.ReaderAt, i interface{}, at uint32) error {
	size, err := struc.Sizeof(i)
	if err != nil {
		return err
	}
	return struc.UnpackWithOrder(io.NewSectionReader(r, int64(at), int64(size)), i, binary.LittleEndian)
}

func NewReesesLoader(r io.ReaderAt, arch string) (models.Loader, error) {
	var header reesesHeader
	// loader.reesesHeader{OffLoadSec:0x20, OffReg:0x5c, NumLoad:0x3, NumReg:0x3, OffHash:0x1120, FakeStartAddr:0x4020a8}
	if err := unpackAt(r, &header, 0); err != nil {
		return nil, err
	}
	loads := make([]reesesLoad, header.NumLoad)
	if err := unpackAt(r, &loads, header.OffLoadSec); err != nil {
		return nil, err
	}
	regs := make([]ReesesReg, header.NumReg)
	if err := unpackAt(r, &regs, header.OffReg); err != nil {
		return nil, err
	}
	var entry uint32
	for _, v := range regs {
		if v.Num == 32 {
			entry = v.Val
		}
	}
	return &ReesesLoader{
		LoaderBase: LoaderBase{
			arch:      "mips",
			bits:      32,
			os:        "reeses",
			entry:     uint64(entry),
			byteOrder: binary.LittleEndian,
		},
		Regs:  regs,
		Loads: loads,
		r:     r,
	}, nil
}

func (r *ReesesLoader) Segments() ([]models.SegmentData, error) {
	var segs []models.SegmentData
	// map surrounding region so stack works
	segs = append(segs, models.SegmentData{
		Off:  0,
		Addr: 0x400000,
		Size: 0x30000,
		Prot: 7,
		DataFunc: func() ([]byte, error) {
			return nil, nil
		},
	})
	for _, load := range r.Loads {
		length := load.Length
		offset := load.Offset
		segs = append(segs, models.SegmentData{
			Off:  uint64(load.Offset),
			Addr: uint64(load.Addr),
			Size: uint64(load.Length),
			Prot: 7,
			DataFunc: func() ([]byte, error) {
				p := make([]byte, length)
				n, err := r.r.ReadAt(p, int64(offset))
				return p[:n], err
			},
		})
	}
	return segs, nil
}
