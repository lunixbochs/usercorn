package linux

import (
	"bytes"
	"crypto/rand"
	"github.com/lunixbochs/struc"
	"os"

	"github.com/lunixbochs/usercorn/go/models"
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
	ELF_AT_PLATFORM
	ELF_AT_HWCAP
	ELF_AT_CLKTCK       = 17
	ELF_AT_RANDOM       = 25
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

func setupElfAuxv(u models.Usercorn) ([]Elf64Auxv, error) {
	// set up AT_RANDOM
	var tmp [16]byte
	if _, err := rand.Read(tmp[:]); err != nil {
		return nil, err
	}
	randAddr, err := u.PushBytes(tmp[:])
	if err != nil {
		return nil, err
	}
	// insert platform string
	platformAddr, err := u.PushBytes([]byte(u.Loader().Arch() + "\x00"))
	if err != nil {
		return nil, err
	}
	// main auxv table
	auxv := []Elf64Auxv{
		// TODO: set/track a page size somewhere - on Arch.OS?
		{ELF_AT_PAGESZ, 4096},
		{ELF_AT_BASE, u.InterpBase()},
		{ELF_AT_FLAGS, 0},
		{ELF_AT_ENTRY, uint64(u.BinEntry())},
		{ELF_AT_UID, uint64(os.Getuid())},
		{ELF_AT_EUID, uint64(os.Geteuid())},
		{ELF_AT_GID, uint64(os.Getgid())},
		{ELF_AT_EGID, uint64(os.Getegid())},
		{ELF_AT_PLATFORM, platformAddr},
		{ELF_AT_CLKTCK, 100}, // 100hz, totally fake
		{ELF_AT_RANDOM, randAddr},
		{ELF_AT_NULL, 0},
	}
	// add phdr information if present in binary
	phdrOff, _, phdrCount := u.Loader().Header()
	segments, _ := u.Loader().Segments()
	for _, s := range segments {
		if s.ContainsPhys(phdrOff) {
			phdrOff += s.Addr
			break
		}
	}
	phdrEnt := 56
	if u.Bits() == 32 {
		phdrEnt = 32
	}
	if phdrOff > 0 {
		auxv = append([]Elf64Auxv{
			{ELF_AT_PHDR, phdrOff},
			{ELF_AT_PHENT, uint64(phdrEnt)},
			{ELF_AT_PHNUM, uint64(phdrCount)},
		}, auxv...)
	}
	return auxv, nil
}

func SetupElfAuxv(u models.Usercorn) ([]byte, error) {
	var buf bytes.Buffer
	auxv, err := setupElfAuxv(u)
	if err != nil {
		return nil, err
	}
	if u.Bits() == 32 {
		var auxv32 Elf32Auxv
		for _, a := range auxv {
			auxv32.Type = uint32(a.Type)
			auxv32.Val = uint32(a.Val)
			if err := struc.PackWithOrder(&buf, &auxv32, u.ByteOrder()); err != nil {
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
