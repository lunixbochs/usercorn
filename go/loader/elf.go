package loader

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"strings"

	"github.com/lunixbochs/usercorn/go/models"
)

var machineMap = map[elf.Machine]string{
	elf.EM_386:    "x86",
	elf.EM_X86_64: "x86_64",
	elf.EM_ARM:    "arm",
	elf.EM_MIPS:   "mips",
	elf.EM_PPC:    "ppc",
	elf.EM_PPC64:  "ppc64",
	elf.EM_SPARC:  "sparc",

	// TODO: if minimum version is bumped to Go 1.6, use the native enum elf.EM_AARCH64
	183: "arm64",
}

type ElfLoader struct {
	LoaderBase
	file *elf.File

	phoff, shoff     uint64
	phentsize, phnum int
	shentsize, shnum int
	shstrndx         int
	phdr             []byte
}

var elfMagic = []byte{0x7f, 0x45, 0x4c, 0x46}

func MatchElf(r io.ReaderAt) bool {
	return bytes.Equal(getMagic(r), elfMagic)
}

func NewElfLoader(r io.ReaderAt, arch string) (models.Loader, error) {
	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	machineName, ok := machineMap[file.Machine]
	if !ok {
		return nil, errors.Errorf("Unsupported machine: %s", file.Machine)
	}
	l := &ElfLoader{
		LoaderBase: LoaderBase{
			arch:      machineName,
			os:        "linux",
			entry:     file.Entry,
			byteOrder: file.ByteOrder,
		},
		file: file,
	}
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	switch file.Class {
	case elf.ELFCLASS32:
		l.bits = 32
		var hdr elf.Header32
		if err := binary.Read(sr, file.ByteOrder, &hdr); err != nil {
			return nil, errors.Wrap(err, "failed to read file header")
		}
		l.phoff, l.phentsize, l.phnum = uint64(hdr.Phoff), int(hdr.Phentsize), int(hdr.Phnum)
		l.shoff, l.shentsize, l.shnum = uint64(hdr.Shoff), int(hdr.Shentsize), int(hdr.Shnum)
		l.shstrndx = int(hdr.Shstrndx)
	case elf.ELFCLASS64:
		l.bits = 64
		var hdr elf.Header64
		if err := binary.Read(sr, file.ByteOrder, &hdr); err != nil {
			return nil, errors.Wrap(err, "failed to read file header")
		}
		l.phoff, l.phentsize, l.phnum = uint64(hdr.Phoff), int(hdr.Phentsize), int(hdr.Phnum)
		l.shoff, l.shentsize, l.shnum = uint64(hdr.Shoff), int(hdr.Shentsize), int(hdr.Shnum)
	default:
		return nil, errors.New("Unknown ELF class.")
	}
	l.phdr = make([]byte, l.phentsize*l.phnum)
	r.ReadAt(l.phdr, int64(l.phoff))
	return l, nil
}

func (e *ElfLoader) Interp() string {
	for _, prog := range e.file.Progs {
		if prog.Type == elf.PT_INTERP {
			data, _ := ioutil.ReadAll(prog.Open())
			return strings.TrimRight(string(data), "\x00")
		}
	}
	return ""
}

func (e *ElfLoader) Header() (uint64, []byte, int) {
	return e.phoff, e.phdr, e.phnum
}

func (e *ElfLoader) Type() int {
	switch e.file.Type {
	case elf.ET_EXEC:
		return EXEC
	case elf.ET_DYN:
		return DYN
	default:
		return UNKNOWN
	}
}

func (e *ElfLoader) DataSegment() (start, end uint64) {
	sec := e.file.Section(".data")
	if sec != nil {
		return sec.Addr, sec.Addr + sec.Size
	}
	return 0, 0
}

func (e *ElfLoader) Segments() ([]models.SegmentData, error) {
	ret := make([]models.SegmentData, 0, len(e.file.Progs))
	for _, prog := range e.file.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		filesz := prog.Filesz
		stream := prog.Open()
		prot := 0
		if prog.Flags&elf.PF_R != 0 {
			prot |= 1
		}
		if prog.Flags&elf.PF_W != 0 {
			prot |= 2
		}
		if prog.Flags&elf.PF_X != 0 {
			prot |= 4
		}
		ret = append(ret, models.SegmentData{
			Off:  prog.Off,
			Addr: prog.Vaddr,
			Size: prog.Memsz,
			Prot: prot,
			DataFunc: func() ([]byte, error) {
				data := make([]byte, filesz)
				_, err := stream.Read(data)
				// swallow EOF so we can still load broken binaries
				if err == io.EOF {
					err = nil
				}
				return data, err
			},
		})
	}
	return ret, nil
}

func (e *ElfLoader) getSymbols() ([]models.Symbol, error) {
	syms, err := e.file.Symbols()
	if err != nil {
		return []models.Symbol{}, err
	}
	symbols := make([]models.Symbol, 0, len(syms))
	for _, s := range syms {
		symbols = append(symbols, models.Symbol{
			Name:    s.Name,
			Start:   s.Value,
			End:     s.Value + s.Size,
			Dynamic: false,
		})
	}
	// don't care about missing dyn symtab
	dyn, _ := e.file.DynamicSymbols()
	for _, s := range dyn {
		symbols = append(symbols, models.Symbol{
			Name:    s.Name,
			Start:   s.Value,
			End:     s.Value + s.Size,
			Dynamic: true,
		})
	}
	return symbols, nil
}

func (e *ElfLoader) Symbols() ([]models.Symbol, error) {
	var err error
	if e.symCache == nil {
		e.symCache, err = e.getSymbols()
	}
	return e.symCache, err
}

func (e *ElfLoader) DWARF() (*dwarf.Data, error) {
	return e.file.DWARF()
}
