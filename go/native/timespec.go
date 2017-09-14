package native

import "time"

type Timespec struct {
	Sec  int64 `struc:"off_t"`
	Nsec int64 `struc:"off_t"`
}

func (t *Timespec) Duration() time.Duration {
	return time.Duration(t.Sec)*time.Second + time.Duration(t.Nsec)*time.Nanosecond
}
