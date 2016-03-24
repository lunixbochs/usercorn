package models

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"github.com/lunixbochs/struc"
	"hash/crc32"
)

// savestate format:
// https://github.com/lunixbochs/usercorn/issues/176

// file header
// uint32(savestate format version)
// uint32(crc32 of compressed data)
// uint64(length of compressed data)
// remainder is gzip-compressed
//
// -- uncompressed data start --
// unicorn header
// uint32(unicorn major version)
// uint32(unicorn minor version)
// uint32(unicorn arch enum)
// uint32(unicorn mode enum)
//
// registers
// uint32(number of registers)
// 1..num: uint32(register enum), uint64(register value)
//
// memory
// uint64(number of mapped sections)
// 1..num: uint64(addr), uint64(len), uint32(prot), <raw memory bytes of len>

func Save(u Usercorn) ([]byte, error) {
	var buf bytes.Buffer
	arch := u.Arch()
	options := &struc.Options{Order: binary.BigEndian}
	// build compressed body
	s := StrucStream{&buf, options}

	// unicorn header
	// unicorn version isn't exposed by Go bindings yet (Unicorn PR #483)
	s.Pack(uint32(0), uint32(0))
	s.Pack(uint32(arch.UC_ARCH), uint32(arch.UC_MODE))

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
			return nil, err
		}
		buf.Write(mem)
	}

	// compress body
	var tmp bytes.Buffer
	gz := gzip.NewWriter(&tmp)
	buf.WriteTo(gz)
	buf.Reset()
	data := tmp.Bytes()

	// write file header
	var final bytes.Buffer
	s = StrucStream{&final, options}
	s.Pack(uint32(1), crc32.ChecksumIEEE(data), uint32(len(data)))
	tmp.WriteTo(&final)
	return final.Bytes(), nil
}
