package loader

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"../models"
)

var machoCpuMap = map[macho.Cpu]string{
	macho.Cpu386:   "x86",
	macho.CpuAmd64: "x86_64",
	macho.CpuArm:   "arm",
	macho.CpuPpc:   "ppc",
	macho.CpuPpc64: "ppc64",
}

var machoMagics = [][]byte{
	{0xca, 0xfe, 0xba, 0xbe},
	{0xfe, 0xed, 0xfa, 0xce},
	{0xfe, 0xed, 0xfa, 0xcf},
	{0xce, 0xfa, 0xed, 0xfe},
	{0xcf, 0xfa, 0xed, 0xfe},
}

type MachOLoader struct {
	LoaderHeader
	file *macho.File
}

func findEntry(f *macho.File, bits int) (uint64, error) {
	var entry uint64
	for _, l := range f.Loads {
		// TODO: LC_MAIN == 0x28?
		var cmd macho.LoadCmd
		data := l.Raw()
		binary.Read(bytes.NewReader(data), f.ByteOrder, &cmd)
		if cmd == macho.LoadCmdUnixThread {
			if bits == 64 {
				ip := 144
				binary.Read(bytes.NewReader(data[ip:ip+8]), f.ByteOrder, &entry)
			} else {
				var ent32 uint32
				ip := 56
				binary.Read(bytes.NewReader(data[ip:ip+4]), f.ByteOrder, &ent32)
				entry = uint64(ent32)
			}
			return entry, nil
		}
	}
	return 0, errors.New("Could not find entry point.")
}

func MatchMachO(r io.ReaderAt) bool {
	magic := getMagic(r)
	for _, check := range machoMagics {
		if bytes.Equal(magic, check) {
			return true
		}
	}
	return false
}

func NewMachOLoader(r io.ReaderAt) (models.Loader, error) {
	file, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	var bits int
	switch file.Magic {
	case macho.Magic32:
		bits = 32
	case macho.Magic64:
		bits = 64
	default:
		return nil, errors.New("Unknown ELF class.")
	}
	machineName, ok := machoCpuMap[file.Cpu]
	if !ok {
		return nil, fmt.Errorf("Unsupported CPU: %s", file.Cpu)
	}
	entry, err := findEntry(file, bits)
	if err != nil {
		return nil, err
	}
	return &MachOLoader{
		LoaderHeader: LoaderHeader{
			arch:  machineName,
			bits:  bits,
			os:    "darwin",
			entry: entry,
		},
		file: file,
	}, nil
}

func (m *MachOLoader) Interp() string {
	return ""
}

func (m *MachOLoader) Header() (uint64, []byte, int) {
	return 0, nil, 0
}

func (m *MachOLoader) Type() int {
	return EXEC
}

func (m *MachOLoader) DataSegment() (start, end uint64) {
	seg := m.file.Segment("__DATA")
	if seg != nil {
		return seg.Addr, seg.Addr + seg.Memsz
	}
	return 0, 0
}

func (m *MachOLoader) Segments() ([]models.SegmentData, error) {
	ret := make([]models.SegmentData, 0, len(m.file.Loads))
	for _, l := range m.file.Loads {
		if s, ok := l.(*macho.Segment); ok {
			switch s.Cmd {
			case macho.LoadCmdSegment, macho.LoadCmdSegment64:
				ret = append(ret, models.SegmentData{
					Off:  s.Offset,
					Addr: s.Addr,
					Size: s.Memsz,
					DataFunc: func() ([]byte, error) {
						return s.Data()
					},
				})
			}
		}
	}
	return ret, nil
}

func (m *MachOLoader) getSymbols() ([]models.Symbol, error) {
	var symbols []models.Symbol
	if m.file.Symtab == nil {
		return nil, errors.New("no symbol table found")
	} else {
		syms := m.file.Symtab.Syms
		symbols := make([]models.Symbol, len(syms))
		for i, s := range syms {
			symbols[i] = models.Symbol{
				Name:  s.Name,
				Start: s.Value,
				End:   0,
			}
		}
	}
	if m.file.Dysymtab != nil {
		for _, v := range m.file.Dysymtab.IndirectSyms {
			symbols[v].Dynamic = true
		}
	}
	return symbols, nil
}

func (m *MachOLoader) Symbols() ([]models.Symbol, error) {
	var err error
	if m.symCache == nil {
		m.symCache, err = m.getSymbols()
	}
	return m.symCache, err
}
