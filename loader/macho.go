package loader

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

func NewMachOLoader(r io.ReaderAt) (Loader, error) {
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

func (m *MachOLoader) Segments() ([]Segment, error) {
	ret := make([]Segment, 0, len(m.file.Loads))
	for _, l := range m.file.Loads {
		if s, ok := l.(*macho.Segment); ok {
			switch s.Cmd {
			case macho.LoadCmdSegment, macho.LoadCmdSegment64:
				data, err := s.Data()
				if err != nil {
					return nil, err
				}
				ret = append(ret, Segment{
					Addr: s.Addr,
					Data: data,
				})
			}
		}
	}
	return ret, nil
}

func (m *MachOLoader) Symbolicate(addr uint64) (string, error) {
	nearest := make(map[uint64][]macho.Symbol)
	for _, sym := range m.file.Symtab.Syms {
		dist := addr - sym.Value
		if dist > 0 {
			nearest[dist] = append(nearest[dist], sym)
		}
	}
	if len(nearest) > 0 {
		for dist, v := range nearest {
			sym := v[0]
			return fmt.Sprintf("%s+0x%x", sym.Name, dist), nil
		}
	}
	return "", nil
}
