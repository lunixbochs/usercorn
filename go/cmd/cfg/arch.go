package main

import (
	cs "github.com/bnagy/gapstone"

	"github.com/lunixbochs/usercorn/go/models"
)

type archConfig struct {
	CondJmps []int
	Jmps     []int
	Call     int
	Ret      int
}

func ArchConfig(u models.Usercorn) *archConfig {
	switch u.Arch().Radare {
	case "x86", "x86_64":
		condJmps := []int{
			cs.X86_INS_JA,
			cs.X86_INS_JAE,
			cs.X86_INS_JB,
			cs.X86_INS_JBE,
			cs.X86_INS_JCXZ,
			cs.X86_INS_JE,
			cs.X86_INS_JECXZ,
			cs.X86_INS_JG,
			cs.X86_INS_JGE,
			cs.X86_INS_JL,
			cs.X86_INS_JLE,
			cs.X86_INS_JNE,
			cs.X86_INS_JNO,
			cs.X86_INS_JNP,
			cs.X86_INS_JNS,
			cs.X86_INS_JO,
			cs.X86_INS_JP,
			cs.X86_INS_JRCXZ,
			cs.X86_INS_JS,
		}
		jmps := []int{
			cs.X86_INS_JMP,
			cs.X86_INS_LOOP,
			cs.X86_INS_LOOPE,
			cs.X86_INS_LOOPNE,
		}
		return &archConfig{
			CondJmps: condJmps,
			Jmps:     jmps,
			Call:     cs.X86_INS_CALL,
			Ret:      cs.X86_INS_RET,
		}
	default:
		panic("unknown arch")
	}
}
