package native

type Timeval struct {
	Sec  int64 `struc:"off_t"`
	Usec int64 `struc:"off_t"`
}
