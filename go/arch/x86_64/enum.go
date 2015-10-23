package x86_64

import "github.com/lunixbochs/usercorn/go/syscalls"

type A syscalls.A

const (
	INT  = syscalls.INT
	ENUM = syscalls.ENUM
	PTR  = syscalls.PTR
)
