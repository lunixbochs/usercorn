package posix

import (
	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

type PosixKernel struct {
	common.KernelBase
	Unpack func(common.Buf, interface{})
}

func pushAddrs(u models.Usercorn, addrs []uint64) error {
	if _, err := u.Push(0); err != nil {
		return err
	}
	for i, _ := range addrs {
		if _, err := u.Push(addrs[len(addrs)-i-1]); err != nil {
			return err
		}
	}
	return nil
}

func pushStrings(u models.Usercorn, args ...string) ([]uint64, error) {
	addrs := make([]uint64, 0, len(args)+1)
	for _, arg := range args {
		if addr, err := u.PushBytes([]byte(arg + "\x00")); err != nil {
			return nil, err
		} else {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

func StackInit(u models.Usercorn, args, env []string, auxv []byte) error {
	// push argv and envp strings
	envp, err := pushStrings(u, env...)
	if err != nil {
		return err
	}
	argv, err := pushStrings(u, args...)
	if err != nil {
		return err
	}
	// align stack pointer
	sp, _ := u.RegRead(u.Arch().SP)
	u.RegWrite(u.Arch().SP, (sp & ^uint64(15)))
	// end marker
	if _, err := u.Push(0); err != nil {
		return err
	}
	// auxv
	if len(auxv) > 0 {
		if _, err := u.PushBytes(auxv); err != nil {
			return err
		}
	}
	// envp
	if err := pushAddrs(u, envp); err != nil {
		return err
	}
	// argv
	if err := pushAddrs(u, argv); err != nil {
		return err
	}
	// argc
	_, err = u.Push(uint64(len(args)))
	return err
}
