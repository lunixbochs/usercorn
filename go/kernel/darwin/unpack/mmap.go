package unpack

import (
	"github.com/lunixbochs/usercorn/go/models/cpu"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

var mmapProtMap = map[int]int{
	0: cpu.PROT_NONE,
	1: cpu.PROT_READ,
	2: cpu.PROT_WRITE,
	4: cpu.PROT_EXEC,
}

func MmapProt(reg uint64) enum.MmapProt {
	var out enum.MmapProt
	for a, b := range mmapProtMap {
		if int(reg)&a == a {
			out |= enum.MmapProt(b)
		}
	}
	return out
}

func MmapFlag(reg uint64) enum.MmapFlag {
	var out enum.MmapFlag
	for a, b := range mmapFlagMap {
		if int(reg)&a == a {
			out |= enum.MmapFlag(b)
		}
	}
	return out
}
