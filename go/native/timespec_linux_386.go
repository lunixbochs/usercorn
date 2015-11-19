package native

import "syscall"

func (t *Timespec) Native() *syscall.Timeval {
	return &syscall.Timeval{Sec: int32(t.Sec), Usec: int32(t.Nsec / 1000)}
}
