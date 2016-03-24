package models

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"github.com/lunixbochs/struc"
	"os"
)

// savestate format:
// https://github.com/lunixbochs/usercorn/issues/176

// file header
// uint32(savestate format version)
// -- unicorn header --
// uint32(unicorn major version)
// uint32(unicorn minor version)
// uint32(unicorn arch enum)
// uint32(unicorn mode enum)
//
// -- compressed data header --
// uint64(length of compressed data)
// remainder is gzip-compressed
//
// -- uncompressed data start --
// registers
// uint32(number of registers)
// 1..num: uint32(register enum), uint64(register value)
//
// memory
// uint64(number of mapped sections)
// 1..num: uint64(addr), uint64(len), uint32(prot), <raw memory bytes of len>

type SaveHeader struct {
	Version          uint32
	UcMajor, UcMinor uint32
	UcArch, UcMode   uint32

	BodySize   uint64 `struc:"sizeof=Compressed"`
	Compressed []byte
}

func (s *SaveHeader) PackBody(b *SaveBody) error {
	var tmp bytes.Buffer
	gz := gzip.NewWriter(&tmp)
	err := struc.PackWithOptions(gz, b, &struc.Options{Order: binary.BigEndian})
	if err != nil {
		return err
	}
	s.Compressed = tmp.Bytes()
	return nil
}

func (s *SaveHeader) UnpackBody() (*SaveBody, error) {
	gz, err := gzip.NewReader(bytes.NewReader(s.Compressed))
	if err != nil {
		return nil, err
	}
	body := &SaveBody{}
	err = struc.UnpackWithOptions(gz, body, &struc.Options{Order: binary.BigEndian})
	if err != nil {
		return nil, err
	}
	return body, nil
}

type SaveReg struct {
	Enum, Val uint64
}

type SaveMem struct {
	Addr, Size uint64
	Prot       uint32

	Len  uint64 `struc:"sizeof=Data"`
	Data []byte
}

type SaveBody struct {
	RegCount uint64 `struc:"sizeof=Regs"`
	Regs     []SaveReg
	MemCount uint64 `struc:"sizeof=Mem"`
	Mem      []SaveMem
}

// TODO: pack using all structs above instead of just header
func Save(u Usercorn) ([]byte, error) {
	var buf bytes.Buffer
	arch := u.Arch()
	options := &struc.Options{Order: binary.BigEndian}
	// build compressed body
	s := StrucStream{&buf, options}

	// register list
	s.Pack(uint64(len(arch.Regs)))
	for _, enum := range arch.Regs {
		val, _ := u.RegRead(enum)
		s.Pack(uint64(enum), uint64(val))
	}

	// memory mappings
	mappings := u.Mappings()
	s.Pack(uint64(len(mappings)))
	for _, m := range mappings {
		s.Pack(uint64(m.Addr), uint64(m.Size), uint32(m.Prot))
		mem, err := u.MemRead(m.Addr, m.Size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: error saving memory at 0x%x-0x%x: %s\n", m.Addr, m.Addr+m.Size, err)
			continue
		}
		buf.Write(mem)
	}

	// compress body
	var tmp bytes.Buffer
	gz := gzip.NewWriter(&tmp)
	buf.WriteTo(gz)
	buf.Reset()

	// write header / combine everything
	header := &SaveHeader{
		Version: 1,
		// unicorn version isn't exposed by Go bindings yet (Unicorn PR #483)
		UcMajor: 0, UcMinor: 0,
		UcArch: uint32(arch.UC_ARCH), UcMode: uint32(arch.UC_MODE),
		Compressed: tmp.Bytes(),
	}
	var final bytes.Buffer
	struc.PackWithOptions(&final, header, options)
	return final.Bytes(), nil
}
