package models

import (
	"bytes"
	"github.com/lunixbochs/struc"
)

const (
	ELF_AT_NULL = iota
	ELF_AT_IGNORE
	ELF_AT_EXECFD
	ELF_AT_PHDR
	ELF_AT_PHENT
	ELF_AT_PHNUM
	ELF_AT_PAGESZ
	ELF_AT_BASE
	ELF_AT_FLAGS
	ELF_AT_ENTRY
	ELF_AT_NOTELF
	ELF_AT_UID
	ELF_AT_EUID
	ELF_AT_GID
	ELF_AT_EGID
	ELF_AT_CLKTCK       = 17
	ELF_AT_SYSINFO      = 32
	ELF_AT_SYSINFO_EHDR = 33
)

type Elf32Auxv struct {
	Type, Val uint32
}

type Elf64Auxv struct {
	Type, Val uint64
}

func add(auxv []Elf64Auxv, t, val uint64) []Elf64Auxv {
	return append(auxv, Elf64Auxv{t, val})
}

func setupElfAuxv(u Usercorn) ([]Elf64Auxv, error) {
	auxv := make([]Elf64Auxv, 0, 20)
	phdr, phdrCount := u.Loader().Header()
	phdrAddr, err := u.MmapWrite(0, phdr)
	if err != nil {
		return nil, err
	}
	auxv = add(auxv, ELF_AT_PHDR, phdrAddr)
	auxv = add(auxv, ELF_AT_PHENT, uint64(u.Bits()*8*2))
	auxv = add(auxv, ELF_AT_PHNUM, uint64(phdrCount))
	auxv = add(auxv, ELF_AT_ENTRY, uint64(u.BinEntry()))
	// TODO: set/track a page size somewhere - on Arch.OS?
	auxv = add(auxv, ELF_AT_PAGESZ, 0x1000)
	auxv = add(auxv, ELF_AT_BASE, u.InterpBase())
	// TODO: set proper uid/gid (portable?)
	auxv = add(auxv, ELF_AT_UID, 0)
	auxv = add(auxv, ELF_AT_EUID, 0)
	auxv = add(auxv, ELF_AT_GID, 0)
	auxv = add(auxv, ELF_AT_EGID, 0)
	auxv = add(auxv, ELF_AT_NULL, 0)
	return auxv, nil
}

func SetupElfAuxv(u Usercorn) ([]byte, error) {
	var buf bytes.Buffer
	auxv, err := setupElfAuxv(u)
	if err != nil {
		return nil, err
	}
	if u.Bits() == 32 {
		auxv32 := make([]Elf32Auxv, len(auxv))
		for i, v := range auxv {
			auxv32[i].Type = uint32(v.Type)
			auxv32[i].Val = uint32(v.Val)
		}
		for _, a := range auxv32 {
			if err := struc.PackWithOrder(&buf, &a, u.ByteOrder()); err != nil {
				return nil, err
			}
		}
	} else {
		for _, a := range auxv {
			if err := struc.PackWithOrder(&buf, &a, u.ByteOrder()); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), err
}
