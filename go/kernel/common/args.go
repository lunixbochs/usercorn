package common

import (
	"github.com/lunixbochs/usercorn/go/models"
)

func StackArgs(u models.Usercorn) func(n int) ([]uint64, error) {
	return func(n int) ([]uint64, error) {
		_, err := u.Pop()
		if err != nil {
			return nil, err
		}
		ret := make([]uint64, n)
		for i := 0; i < n; i++ {
			v, err := u.Pop()
			if err != nil {
				return nil, err
			}
			ret[i] = v
		}
		return ret, nil
	}
}

func RegArgs(u models.Usercorn, regs []int) func(n int) ([]uint64, error) {
	return func(n int) ([]uint64, error) {
		return u.ReadRegs(regs[:n])
	}
}
