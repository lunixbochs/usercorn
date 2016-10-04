package common

import (
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
	return func(n int) ([]uint64, error) {
		vals := make([]uint64, n)
		for i, enum := range regs[:n] {
			val, err := u.RegRead(enum)
			if err != nil {
				return nil, err
			}
			vals[i] = val
		}
		return vals[:n], nil
	}
}

func RegArgsShifted(u models.Usercorn, regs []int, shift int)  func(n int) ([]uint64, error) {
	return func(n int) ([]uint64, error) {
		return u.ReadRegs(regs[shift:n+shift])
	}
}
