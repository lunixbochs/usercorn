package loader

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

var machineMap = map[elf.Machine]string{
	elf.EM_386:    "x86",
	elf.EM_X86_64: "x86_64",
	elf.EM_ARM:    "arm",
	elf.EM_MIPS:   "mips",
	elf.EM_PPC:    "ppc",
	elf.EM_PPC64:  "ppc64",
}

type ElfLoader struct {
	LoaderHeader
	file *elf.File
}

var elfMagic = []byte{0x7f, 0x45, 0x4c, 0x46}

func MatchElf(r io.ReaderAt) bool {
	return bytes.Equal(getMagic(r), elfMagic)
}

func NewElfLoader(r io.ReaderAt) (Loader, error) {
	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	var bits int
	switch file.Class {
	case elf.ELFCLASS32:
		bits = 32
	case elf.ELFCLASS64:
		bits = 64
	default:
		return nil, errors.New("Unknown ELF class.")
	}
	machineName, ok := machineMap[file.Machine]
	if !ok {
		return nil, fmt.Errorf("Unsupported machine: %s", file.Machine)
	}
	return &ElfLoader{
		LoaderHeader: LoaderHeader{
			arch:  machineName,
			bits:  bits,
			os:    "linux",
			entry: file.Entry,
		},
		file: file,
	}, nil
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

func (e *ElfLoader) Segments() ([]Segment, error) {
	ret := make([]Segment, 0, len(e.file.Progs))
	for _, prog := range e.file.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		data := make([]byte, prog.Memsz)
		prog.Open().Read(data)
		ret = append(ret, Segment{
			Addr: prog.Vaddr,
			Data: data,
		})
	}
	return ret, nil
}

func (e *ElfLoader) Symbolicate(addr uint64) (string, error) {
	nearest := make(map[uint64][]elf.Symbol)
	syms, err := e.file.Symbols()
	if err != nil {
		return "", err
	}
	var min int64 = -1
	for _, sym := range syms {
		dist := int64(addr - sym.Value)
		if dist > 0 && uint64(dist) <= sym.Size {
			if dist < min || min == -1 {
				min = dist
			}
			nearest[uint64(dist)] = append(nearest[uint64(dist)], sym)
		}
	}
	if len(nearest) > 0 {
		sym := nearest[uint64(min)][0]
		return fmt.Sprintf("%s+0x%x", sym.Name, min), nil
	}
	return "", nil
}
