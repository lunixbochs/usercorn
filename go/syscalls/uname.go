package syscalls

import (
	"github.com/lunixbochs/usercorn/go/models"
)

func trunc(s string, length int) string {
	if length+1 < len(s) {
		return s[:length-1] + "\x00"
	}
	return s + "\x00"
}

func Uname(u models.Usercorn, addr uint64, un *models.Uname) uint64 {
	u.StrucAt(addr).Pack(un)
	/*
		var utsname syscall.Utsname
		if err := syscall.Uname(utsname); err != nil {
			return 1
		}
	*/
	return 0
}
