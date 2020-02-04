package cpu

// base hook enums on Unicorn's for simplicity
// https://github.com/unicorn-engine/unicorn/blob/master/bindings/go/unicorn/unicorn_const.go
const (
	// hook CPU interrupts
	HOOK_INTR = 1

	// hook one instruction (cpu-specific)
	HOOK_INSN = 2

	// hook each executed instruction
	HOOK_CODE = 4

	// hook each executed basic block
	HOOK_BLOCK = 8

	// hook (before) each memory read/write
	HOOK_MEM_READ  = 1024
	HOOK_MEM_WRITE = 2048
	HOOK_MEM_FETCH = 4096
	// HOOK_MEM_READ_AFTER = uc.HOOK_MEM_READ_AFTER

	// hook all memory errors
	HOOK_MEM_ERR = 1008
)

// these errors are used for HOOK_MEM_ERR
const (
	MEM_READ_UNMAPPED  = 19
	MEM_WRITE_UNMAPPED = 20
	MEM_FETCH_UNMAPPED = 21
	MEM_WRITE_PROT     = 12
	MEM_READ_PROT      = 13
	MEM_FETCH_PROT     = 14

	MEM_PROT     = MEM_WRITE_PROT | MEM_READ_PROT | MEM_FETCH_PROT
	MEM_UNMAPPED = MEM_READ_UNMAPPED | MEM_WRITE_UNMAPPED | MEM_FETCH_UNMAPPED
)

// these constants are used for memory protections
const (
	PROT_NONE  = 0
	PROT_READ  = 1
	PROT_WRITE = 2
	PROT_EXEC  = 4
	PROT_ALL   = 7
)

// these constants are used in a hook to specify the type of memory access
const (
	MEM_WRITE = 16
	MEM_READ  = 17
	MEM_FETCH = 18
)
