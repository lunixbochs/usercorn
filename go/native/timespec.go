package native

type Timespec struct {
	Sec  int64 `struc:"off_t"`
	Nsec int64 `struc:"off_t"`
}
