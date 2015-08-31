package models

type Arch struct {
	Bits      int
	Radare    string
	CS_ARCH   int
	CS_MODE   uint
	UC_ARCH   int
	UC_MODE   int
	SP        int
	Syscall   func(Usercorn)
	Interrupt func(Usercorn, uint32)
}
