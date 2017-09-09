package loader

import (
	"bytes"
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"github.com/pkg/errors"
	"io"

	"github.com/lunixbochs/usercorn/go/models"
)

const (
	machoLoadCmdReqDyld  = 0x80000000
	machoLoadCmdDylinker = 0xe
	machoLoadCmdMain     = 0x28 | machoLoadCmdReqDyld
)

var machoCpuMap = map[macho.Cpu]string{
	macho.Cpu386:   "x86",
	macho.CpuAmd64: "x86_64",
	macho.CpuArm:   "arm",
	16777228:       "arm64",
	macho.CpuPpc:   "ppc",
	macho.CpuPpc64: "ppc64",
}

var fatMagic = []byte{0xca, 0xfe, 0xba, 0xbe}

var machoMagics = [][]byte{
	fatMagic,
	{0xfe, 0xed, 0xfa, 0xce},
	{0xfe, 0xed, 0xfa, 0xcf},
	{0xce, 0xfa, 0xed, 0xfe},
	{0xcf, 0xfa, 0xed, 0xfe},
}

type MachOLoader struct {
	LoaderBase
	file      *macho.File
	fatOffset uint32
}

func findEntry(f *macho.File, bits int) (uint64, error) {
	var entry uint64
	for _, l := range f.Loads {
		var cmd macho.LoadCmd
		data := l.Raw()
		binary.Read(bytes.NewReader(data), f.ByteOrder, &cmd)
		if cmd == macho.LoadCmdUnixThread {
			// LC_UNIXTHREAD
			if bits == 64 {
				ip := 144
				entry = f.ByteOrder.Uint64(data[ip : ip+8])
			} else {
				ip := 56
				entry = uint64(f.ByteOrder.Uint32(data[ip : ip+4]))
			}
			return entry, nil
		} else if cmd == machoLoadCmdMain {
			// [8:16] == entry - __TEXT, data[16:24] == stack size
			__TEXT := f.Segment("__TEXT")
			if __TEXT == nil {
				return 0, errors.New("Found LC_MAIN but did not find __TEXT segment.")
			}
			entry = f.ByteOrder.Uint64(data[8:16]) + __TEXT.Addr
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

func NewMachOLoader(r io.ReaderAt, archHint string) (models.Loader, error) {
	var (
		file      *macho.File
		fatFile   *macho.FatFile
		err       error
		fatOffset uint32
	)
	magic := getMagic(r)
	if bytes.Equal(magic, fatMagic) {
		fatFile, err = macho.NewFatFile(r)
		if fatFile != nil {
			for _, arch := range fatFile.Arches {
				if machineName, ok := machoCpuMap[arch.Cpu]; ok {
					if machineName == archHint || archHint == "any" {
						file = arch.File
						fatOffset = arch.Offset
						break
					}
				}
			}
			if file == nil {
				return nil, errors.Errorf("Could not find fat binary entry for arch '%s'.", archHint)
			}
		}
	} else {
		file, err = macho.NewFile(r)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to open MachO file")
	}
	var bits int
	switch file.Magic {
	case macho.Magic32:
		bits = 32
	case macho.Magic64:
		bits = 64
	default:
		return nil, errors.New("Unknown magic.")
	}
	machineName, ok := machoCpuMap[file.Cpu]
	if !ok {
		return nil, errors.Errorf("Unsupported CPU: %s", file.Cpu)
	}
	entry, err := findEntry(file, bits)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	m := &MachOLoader{
		LoaderBase: LoaderBase{
			arch:  machineName,
			bits:  bits,
			os:    "darwin",
			entry: entry,
		},
		file:      file,
		fatOffset: fatOffset,
	}
	return m, nil
}

func (m *MachOLoader) Interp() string {
	for _, l := range m.file.Loads {
		var cmd macho.LoadCmd
		data := l.Raw()
		binary.Read(bytes.NewReader(data), m.file.ByteOrder, &cmd)
		if cmd == machoLoadCmdDylinker {
			length := m.file.ByteOrder.Uint32(data[8:12])
			dylinker := data[12 : 13+length]
			return string(dylinker)
		}
	}
	return ""
}

func (m *MachOLoader) Header() (uint64, []byte, int) {
	__TEXT := m.file.Segment("__TEXT")
	if __TEXT != nil {
		return __TEXT.Addr, nil, 0
	}
	return 0, nil, 0
}

func (m *MachOLoader) Type() int {
	switch m.file.Type {
	case macho.TypeExec:
		return EXEC
	case macho.TypeDylib, 0x7: // type dylinker
		return DYN
	default:
		return EXEC
	}
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
				if s.Name == "__PAGEZERO" {
					continue
				}
				ret = append(ret, models.SegmentData{
					Off:  s.Offset,
					Addr: s.Addr,
					Size: s.Memsz,
					Prot: int(s.Flag) & 7,
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
		symbols = make([]models.Symbol, len(syms))
		for i, s := range syms {
			if s.Sect == 0 || s.Name == "" {
				continue
			}
			symbols[i] = models.Symbol{
				Name:  s.Name,
				Start: s.Value + uint64(m.fatOffset),
				End:   0,
			}
			if i > 0 {
				symbols[i-1].End = symbols[i].Start
			}
		}
	}
	if m.file.Dysymtab != nil {
		for _, v := range m.file.Dysymtab.IndirectSyms {
			if v < uint32(len(symbols)) {
				symbols[v].Dynamic = true
			}
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

func (m *MachOLoader) DWARF() (*dwarf.Data, error) {
	return m.file.DWARF()
}
