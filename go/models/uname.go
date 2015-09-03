package models

import "strings"

type Uname struct {
	Sysname  string
	Nodename string
	Release  string
	Version  string
	Machine  string
}

func pad(s string, length int) string {
	if len(s)+1 > length {
		s = s[:length-1]
	}
	return s + strings.Repeat("\x00", length-len(s))
}

func (u *Uname) Pad(length int) {
	u.Sysname = pad(u.Sysname, length)
	u.Nodename = pad(u.Nodename, length)
	u.Release = pad(u.Release, length)
	u.Version = pad(u.Version, length)
	u.Machine = pad(u.Machine, length)
}
