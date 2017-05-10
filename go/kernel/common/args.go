package common

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

func StackArgs(u models.Usercorn) func(n int) ([]uint64, error) {
	return func(n int) ([]uint64, error) {
		sp, _ := u.RegRead(u.Arch().SP)
		// starts with an empty slot
		s := u.StrucAt(sp + uint64(u.Bits()/8))

		ret := make([]uint64, n)
		for i := 0; i < n; i++ {
			var arg uint64
			// TODO: simplify this when struc issue #47 is fixed
			if u.Bits() == 64 {
				s.Unpack(&arg)
			} else {
				var arg32 uint32
				s.Unpack(&arg32)
				arg = uint64(arg32)
			}
			if s.Error != nil {
				return nil, s.Error
			}
			ret[i] = arg
		}
		return ret, nil
	}
}

func RegArgs(u models.Usercorn, regs []int) func(n int) ([]uint64, error) {
	batch, err := uc.NewRegBatch(regs)
	if err != nil {
		// will only be memory error
		panic(err)
	}
	return func(n int) ([]uint64, error) {
		vals, err := batch.ReadFast(u)
		if err != nil {
			return nil, err
		}
		return vals[:n], nil
	}
}
