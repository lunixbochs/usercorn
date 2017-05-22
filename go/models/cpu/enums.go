package cpu

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

// base hook enums on Unicorn's for simplicity
const (
	// hook CPU interrupts
	HOOK_INTR = uc.HOOK_INTR

	// hook one instruction (cpu-specific)
	HOOK_INSN = uc.HOOK_INSN

	// hook each executed instruction
	HOOK_CODE = uc.HOOK_CODE

	// hook each executed basic block
	HOOK_BLOCK = uc.HOOK_BLOCK

	// hook (before) each memory read/write
	HOOK_MEM_FETCH = uc.HOOK_MEM_FETCH
	HOOK_MEM_READ  = uc.HOOK_MEM_READ
	HOOK_MEM_WRITE = uc.HOOK_MEM_WRITE
	// HOOK_MEM_READ_AFTER = uc.HOOK_MEM_READ_AFTER

	// hook all memory errors
	HOOK_MEM_ERR = uc.HOOK_MEM_INVALID
)

// these errors are used for HOOK_MEM_ERR
const (
	MEM_WRITE_UNMAPPED = uc.MEM_WRITE_UNMAPPED
	MEM_READ_UNMAPPED  = uc.MEM_READ_UNMAPPED
	MEM_FETCH_UNMAPPED = uc.MEM_FETCH_UNMAPPED
	MEM_WRITE_PROT     = uc.MEM_WRITE_PROT
	MEM_READ_PROT      = uc.MEM_READ_PROT
	MEM_FETCH_PROT     = uc.MEM_FETCH_PROT

	MEM_PROT     = MEM_WRITE_PROT | MEM_READ_PROT | MEM_FETCH_PROT
	MEM_UNMAPPED = MEM_READ_UNMAPPED | MEM_WRITE_UNMAPPED | MEM_FETCH_UNMAPPED
)

// these constants are used for memory protections
const (
	PROT_NONE  = uc.PROT_NONE
	PROT_READ  = uc.PROT_READ
	PROT_WRITE = uc.PROT_WRITE
	PROT_EXEC  = uc.PROT_EXEC
	PROT_ALL   = uc.PROT_ALL
)

// these constants are used in a hook to specify the type of memory access
const (
	MEM_WRITE = uc.MEM_WRITE
	MEM_READ  = uc.MEM_READ
	MEM_FETCH = uc.MEM_FETCH
)
