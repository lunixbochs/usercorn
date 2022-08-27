package bpf

import (
	"os"

	"github.com/pkg/errors"

	usercorn "github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

func Main(args []string) {
	c := cmd.NewUsercornRawCmd()
	c.NoArgs = true
	var packet *string

	c.SetupFlags = func() error {
		packet = c.Flags.String("packet", "", "packet file to run filter against")
		return nil
	}

	c.MakeUsercorn = func(filter string) (models.Usercorn, error) {
		l, err := loader.NewBpfLoader(filter, *packet)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load BPF filter")
		}
		u, err := usercorn.NewUsercornRaw(l, c.Config)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create usercorn")
		}

		// Map in both segments separately
		segments, err := l.Segments()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get segments from loader")
		}
		for _, seg := range segments {
			err := u.MemMap(seg.Addr, seg.Size, seg.Prot)
			if err != nil {
				return nil, errors.Wrap(err, "failed to map in address space")
			}

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
	os.Exit(c.Run(args, os.Environ()))
}

func init() { cmd.Register("bpf", "execute a BPF filter binary", Main) }
