package x86_64

import (
	"../../models"
)

var linuxSyscalls = map[int]string{
	0:  "read",
	1:  "write",
	2:  "open",
	3:  "close",
	8:  "lseek",
	9:  "mmap",
	11: "munmap",
	60: "exit",
}

func LinuxSyscall(u models.Usercorn) {
	AbiSyscall(u, linuxSyscalls)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "linux", Syscall: LinuxSyscall, Interrupt: LinuxInterrupt})
}
