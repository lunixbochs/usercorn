package linux

import (
	"fmt"
	"os"
	"syscall"
)

// TODO: put these somewhere. ghostrace maybe.
const (
	PR_SET_VMA      = 0x53564d41
	PR_GET_DUMPABLE = 0x3
	PR_SET_DUMPABLE = 0x4
)

func (k *LinuxKernel) Prctl(code int, arg uint64) uint64 {
	switch code {
	case PR_SET_VMA:
		//TODO: if there is ever an Android kernel, this is Android only
		return 0
	case PR_GET_DUMPABLE:
		return k.IsDumpable
	case PR_SET_DUMPABLE:
		if arg == 0 || arg == 1 {
			k.IsDumpable = arg
			return 0
		} else {
			return UINT64_MAX
		}
	}
	fmt.Fprintf(os.Stderr, "WARNING: unsupported prctl option 0x%x\n", code)
	return uint64(syscall.EINVAL)
}
