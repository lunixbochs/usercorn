package x86_64

import (
	"../../models"
)

var darwinSyscalls = map[int]string{
	1:   "exit",
	2:   "fork",
	3:   "read",
	4:   "write",
	5:   "open",
	6:   "close",
	7:   "wait4",
	9:   "link",
	10:  "unlink",
	73:  "munmap",
	197: "mmap",
	199: "lseek",
}

func DarwinSyscall(u models.Usercorn) {
	AbiSyscall(u, darwinSyscalls)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Syscall: DarwinSyscall, Interrupt: DarwinInterrupt})
}
