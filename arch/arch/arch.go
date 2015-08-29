package arch

type Arch struct {
	Bits int
	Radare string
	CS_ARCH int
	CS_MODE int
	UC_ARCH int
	UC_MODE int
	SP int
    Syscall func()
    Interrupt func()
}
