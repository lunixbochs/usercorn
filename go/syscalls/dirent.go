package syscalls

const (
	DT_UNKNOWN = 0
	DT_FIFO    = 1
	DT_CHR     = 2
	DT_DIR     = 4
	DT_BLK     = 6
	DT_REG     = 8
	DT_LNK     = 10
	DT_SOCK    = 12
	DT_WHT     = 14
)

type LinuxDirent struct {
	Ino  uint64 `struc:"uint32"`
	Off  uint64 `struc:"uint32"`
	Len  int    `struc:"uint16"`
	Name string
	Type int `struc:"uint8"`
}

type LinuxDirent64 struct {
	Ino  uint64 `struc:"uint64"`
	Off  uint64 `struc:"uint64"`
	Len  int    `struc:"uint16"`
	Name string
	Type int `struc:"uint8"`
}
