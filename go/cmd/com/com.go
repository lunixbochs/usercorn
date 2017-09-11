package main

import (
	"github.com/pkg/errors"
	"os"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

func main() {
	c := cmd.NewUsercornRawCmd()
	c.NoArgs = true

	c.MakeUsercorn = func(exe string) (models.Usercorn, error) {
		l, err := loader.NewComLoader(exe)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load COM file")
		}
		u, err := usercorn.NewUsercornRaw(l, c.Config)

		// Map in entire 16 bit address space
		err = u.MemMap(0, 0x10000, 7)
		if err != nil {
			return nil, errors.Wrap(err, "failed to map in address space")
		}

		// Write in binary's data
		segments, err := l.Segments()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get segments from loader")
		}
		for _, seg := range segments {
			data, err := seg.Data()
			if err != nil {
				return nil, errors.Wrap(err, "failed to read segment data")
			}

			err = u.MemWrite(seg.Addr, data)
			if err != nil {
				return nil, errors.Wrap(err, "failed to write segment data")
			}
		}

		return u, nil
	}
	c.Run(os.Args, os.Environ())
}
