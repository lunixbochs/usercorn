package posix

import "syscall"

const (
	SCHED_NORMAL = 0
	SCHED_FIFO = 1
	SCHED_RR = 2
	SCHED_BATCH = 3
	SCHED_ISO = 4
	SCHED_IDLE = 5
	SCHED_DEADLINE =6
)

func (k *PosixKernel) SchedGetscheduler(pid int) int64 {
	if pid < 0 {
		return int64(syscall.EINVAL)
	}
	return SCHED_NORMAL
}
