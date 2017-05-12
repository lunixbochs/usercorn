package cpu

type Hook interface{}

// This interface abstracts the minimum functionality Usercorn requires in a CPU emulator.
type Cpu interface {
	// memory mapping
	MemMapProt(addr, size uint64, prot int) error
	MemProt(addr, size uint64, prot int) error
	MemUnmap(addr, size uint64) error

	// memory IO
	MemRead(addr, size uint64) ([]byte, error)
	MemReadInto(p []byte, addr uint64) error
	MemWrite(addr uint64, p []byte) error

	// register IO
	RegRead(reg int) (uint64, error)
	RegWrite(reg int, val uint64) error

	// execution
	Start(begin, until uint64) error
	Stop() error

	// hooks
	HookAdd(htype int, cb interface{}, begin, end uint64, extra ...int) (Hook, error)
	HookDel(hook Hook) error

	// save/restore entire CPU state
	ContextSave(reuse interface{}) (interface{}, error)
	ContextRestore(ctx interface{}) error

	// cleanup
	Close() error
}
