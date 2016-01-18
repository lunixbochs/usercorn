package common

import (
	"github.com/lunixbochs/argjoy"
)

func (k *KernelBase) commonArgCodec(arg interface{}, vals []interface{}) error {
	if reg, ok := vals[0].(uint64); ok {
		switch v := arg.(type) {
		case *Buf:
			*v = NewBuf(k.U, reg)
		case *Obuf:
			*v = Obuf(NewBuf(k.U, reg))
		case *Len:
			*v = Len(reg)
		case *Off:
			*v = Off(reg)
		case *Fd:
			*v = Fd(reg)
		case *Ptr:
			*v = Ptr(reg)
		case *string:
			s, err := k.U.Mem().ReadStrAt(reg)
			if err != nil {
				return err
			}
			*v = s
		default:
			return argjoy.NoMatch
		}
		return nil
	}
	return argjoy.NoMatch
}
