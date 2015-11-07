package mock

import (
	"encoding/binary"
	"github.com/lunixbochs/ghostrace/ghost/memio"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type Usercorn struct {
	unicorn.Unicorn
}

func (u *Usercorn) Arch() *models.Arch                      { return nil }
func (u *Usercorn) OS() string                              { return "" }
func (u *Usercorn) Bits() uint                              { return 0 }
func (u *Usercorn) ByteOrder() binary.ByteOrder             { return binary.BigEndian }
func (u *Usercorn) Disas(addr, size uint64) (string, error) { return "", nil }
func (u *Usercorn) Symbolicate(addr uint64) (string, error) { return "", nil }

func (u *Usercorn) Brk(addr uint64) (uint64, error)                 { return 0, nil }
func (u *Usercorn) Mmap(addr, size uint64) (uint64, error)          { return 0, nil }
func (u *Usercorn) MmapWrite(addr uint64, p []byte) (uint64, error) { return 0, nil }
func (u *Usercorn) Mem() memio.MemIO                                { return nil }
func (u *Usercorn) StrucAt(addr uint64) *models.StrucStream         { return nil }

func (u *Usercorn) PackAddr(buf []byte, n uint64) ([]byte, error) { return nil, nil }
func (u *Usercorn) UnpackAddr(buf []byte) uint64                  { return 0 }
func (u *Usercorn) PopBytes(p []byte) error                       { return nil }
func (u *Usercorn) PushBytes(p []byte) (uint64, error)            { return 0, nil }
func (u *Usercorn) Pop() (uint64, error)                          { return 0, nil }
func (u *Usercorn) Push(n uint64) (uint64, error)                 { return 0, nil }
func (u *Usercorn) ReadRegs(reg []int) ([]uint64, error)          { return nil, nil }
func (u *Usercorn) RegDump() ([]models.RegVal, error)             { return nil, nil }

func (u *Usercorn) Exe() string           { return "" }
func (u *Usercorn) Loader() models.Loader { return nil }
func (u *Usercorn) InterpBase() uint64    { return 0 }
func (u *Usercorn) Base() uint64          { return 0 }
func (u *Usercorn) Entry() uint64         { return 0 }
func (u *Usercorn) BinEntry() uint64      { return 0 }

func (u *Usercorn) PrefixPath(s string, force bool) string          { return "" }
func (u *Usercorn) PosixInit(args, env []string, auxv []byte) error { return nil }
func (u *Usercorn) Syscall(num int, name string, getArgs func(n int) ([]uint64, error)) (uint64, error) {
	return 0, nil
}
func (u *Usercorn) Exit(status int) {}
