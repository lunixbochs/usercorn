package posix

import (
	"os"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

type PosixKernel struct {
	*co.KernelBase
	Unpack func(co.Buf, interface{})
	Files  map[co.Fd]*File
}

type File struct {
	Fd    co.Fd
	Path  string
	Mode  int
	Flags int
	// entries/offset currently only used by Linux getdents
	Dirents []os.FileInfo
	Offset  uint64
}

func NewKernel() *PosixKernel {
	return &PosixKernel{
		KernelBase: &co.KernelBase{},
		Files:      make(map[co.Fd]*File),
	}
}

func PackAddrs(u models.Usercorn, addrs []uint64) ([]byte, error) {
	buf := make([]byte, int(u.Bits())/8*(len(addrs)+1))
	pos := buf
	for _, v := range addrs {
		x, err := u.PackAddr(pos, v)
		if err != nil {
			return nil, err
		}
		pos = pos[len(x):]
	}
	return buf, nil
}

func PushStrings(u models.Usercorn, args ...string) ([]uint64, error) {
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
	if _, err := u.Push(0); err != nil {
		return err
	}
	if len(args) > 0 {
		if _, err := u.PushBytes([]byte(args[0] + "\x00")); err != nil {
			return err
		}
	}
	// push argv and envp strings
	envp, err := PushStrings(u, env...)
	if err != nil {
		return err
	}
	argv, err := PushStrings(u, args...)
	if err != nil {
		return err
	}
	// precalc envp -> argc for stack alignment
	envpb, err := PackAddrs(u, envp)
	if err != nil {
		return err
	}
	argvb, err := PackAddrs(u, argv)
	if err != nil {
		return err
	}
	var tmp [8]byte
	argcb, err := u.PackAddr(tmp[:], uint64(len(argv)))
	init := append(argcb, argvb...)
	init = append(init, envpb...)
	// align stack pointer
	sp, _ := u.RegRead(u.Arch().SP)
	sp &= ^uint64(15)
	off := len(init) & 15
	if off > 0 {
		sp -= uint64(16 - off)
	}
	u.RegWrite(u.Arch().SP, sp)
	// auxv
	if len(auxv) > 0 {
		if _, err := u.PushBytes(auxv); err != nil {
			return err
		}
	}
	// write envp -> argc
	u.PushBytes(init)
	return err
}
