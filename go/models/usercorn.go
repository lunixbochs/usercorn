package models

import (
	"github.com/lunixbochs/ghostrace/ghost/memio"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type SysGetArgs func(n int) ([]uint64, error)
type SysCb func(num int, name string, args []uint64, ret uint64, desc string) bool
type SysHook struct {
	Before, After SysCb
}

type MapCb func(addr, size uint64, prot int, desc string, file *cpu.FileDesc)
type UnmapCb func(addr, size uint64)
type ProtCb func(addr, size uint64, prot int)
type MapHook struct {
	Map   MapCb
	Unmap UnmapCb
	Prot  ProtCb
}

type Usercorn interface {
	Task
	Config() *Config
	Run() error
	Trampoline(func() error) error

	Callstack() []Stackframe
	Restart(func(Usercorn, error) error)
	Rewind(n, addr uint64) error

	Gate() *Gate

	Printf(fmt string, args ...interface{})
	Println(s ...interface{})

	Brk(addr uint64) (uint64, error)
	Mem() memio.MemIO
	MapStack(base uint64, size uint64, guard bool) error
	StrucAt(addr uint64) *StrucStream

	DirectRead(addr, size uint64) ([]byte, error)
	DirectWrite(addr uint64, p []byte) error

	RunShellcodeMapped(addr uint64, code []byte, setRegs map[int]uint64, regsClobbered []int) error
	RunShellcode(addr uint64, code []byte, setRegs map[int]uint64, regsClobbered []int) error
	RunAsm(addr uint64, asm string, setRegs map[int]uint64, regsClobbered []int) error

	BreakAdd(desc string, future bool, cb func(u Usercorn, addr uint64)) (*Breakpoint, error)
	BreakDel(b *Breakpoint) error
	Breakpoints() []*Breakpoint
	Symbolicate(addr uint64, includeSource bool) (*Symbol, string)

	Exe() string
	Loader() Loader
	InterpBase() uint64
	Base() uint64
	Entry() uint64
	BinEntry() uint64
	SetEntry(entry uint64)
	SetExit(exit uint64)

        Inscount() uint64

	// TODO: PrefixPath will be replaced by a full VFS subsystem
	PrefixPath(s string, force bool) string

	HookSysAdd(before, after SysCb) *SysHook
	HookSysDel(cb *SysHook)
	HookMapAdd(mapCb MapCb, unmapCb UnmapCb, protCb ProtCb) *MapHook
	HookMapDel(cb *MapHook)

	AddKernel(kernel interface{}, first bool)
	Syscall(num int, name string, getArgs SysGetArgs) (uint64, error)

	Exit(err error)
}
