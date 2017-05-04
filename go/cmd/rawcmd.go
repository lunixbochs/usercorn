package cmd

import (
	"encoding/binary"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

func NewUsercornRawCmd() *UsercornCmd {
	c := NewUsercornCmd()

	var entry *uint64
	var arch, osStr, endian *string
	c.MakeUsercorn = func(exe string) (models.Usercorn, error) {
		var byteOrder binary.ByteOrder
		switch *endian {
		case "little":
			byteOrder = binary.LittleEndian
		case "big":
			byteOrder = binary.BigEndian
		default:
			return nil, errors.Errorf("%s is not a valid byte order ('little' or 'big')", endian)
		}
		var err error
		l := loader.NewNullLoader(*arch, *osStr, byteOrder, *entry)
		u, err := usercorn.NewUsercornRaw(l, c.Config)
		if err != nil {
			return nil, err
		}
		u.SetEntry(*entry)
		return u, nil
	}
	c.SetupFlags = func() error {
		entry = c.Flags.Uint64("entry", 0, "entry point")
		arch = c.Flags.String("arch", "x86", "target architecture")
		osStr = c.Flags.String("os", "linux", "target OS")
		endian = c.Flags.String("endian", "little", "'big' or 'little' endian")
		return nil
	}
	return c
}
