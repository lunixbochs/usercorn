package cpu

import (
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	"github.com/pkg/errors"
)

type Keystone struct {
	Arch ks.Architecture
	Mode ks.Mode
	ks   *ks.Keystone
}

func (k *Keystone) Open() (err error) {
	k.ks, err = ks.New(k.Arch, k.Mode)
	return errors.Wrap(err, "ks.New() failed")
}

func (k *Keystone) Asm(asm string, addr uint64) ([]byte, error) {
	if k.ks == nil {
		if err := k.Open(); err != nil {
			return nil, err
		}
	}
	out, _, ok := k.ks.Assemble(asm, addr)
	if !ok {
		return nil, errors.Wrap(k.ks.LastError(), "ks.Assemble() failed")
	}
	return out, nil
}
