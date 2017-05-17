package cpu

import (
	"encoding/binary"
	"github.com/pkg/errors"
)

func PackUint(order binary.ByteOrder, size int, buf []byte, n uint64) ([]byte, error) {
	if buf == nil {
		buf = make([]byte, size)
	} else if len(buf) < size {
		return nil, errors.Errorf("buffer too small (%d < %d)", len(buf), size)
	}
	switch size {
	case 8:
		order.PutUint64(buf[:size], n)
	case 4:
		order.PutUint32(buf[:size], uint32(n))
	case 2:
		order.PutUint16(buf[:size], uint16(n))
	case 1:
		buf[0] = byte(n)
	default:
		return nil, errors.Errorf("unsupported uint size: %d", size)
	}
	return buf[:size], nil
}

func UnpackUint(order binary.ByteOrder, size int, buf []byte) (uint64, error) {
	switch size {
	case 8:
		return order.Uint64(buf), nil
	case 4:
		return uint64(order.Uint32(buf)), nil
	case 2:
		return uint64(order.Uint16(buf)), nil
	case 1:
		return uint64(buf[0]), nil
	default:
		return 0, errors.Errorf("unsupported uint size: %d", size)
	}
}
