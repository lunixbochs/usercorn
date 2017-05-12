package x86

import (
	cs "github.com/bnagy/gapstone"
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/cpu"
	"github.com/lunixbochs/usercorn/go/cpu/unicorn"
	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Name:   "x86",
	Bits:   32,
	Radare: "x86",

	Cpu: &unicorn.Builder{Arch: uc.ARCH_X86, Mode: uc.MODE_32},
	Dis: &cpu.Capstone{Arch: cs.CS_ARCH_X86, Mode: cs.CS_MODE_32},
	Asm: &cpu.Keystone{Arch: ks.ARCH_X86, Mode: ks.MODE_32},

	PC: uc.X86_REG_EIP,
	SP: uc.X86_REG_ESP,
	Regs: map[string]int{
		"eip": uc.X86_REG_EIP,
		"esp": uc.X86_REG_ESP,
		"ebp": uc.X86_REG_EBP,
		"eax": uc.X86_REG_EAX,
		"ebx": uc.X86_REG_EBX,
		"ecx": uc.X86_REG_ECX,
		"edx": uc.X86_REG_EDX,
		"esi": uc.X86_REG_ESI,
		"edi": uc.X86_REG_EDI,

		"eflags": uc.X86_REG_EFLAGS,

		"cs": uc.X86_REG_CS,
		"ds": uc.X86_REG_DS,
		"es": uc.X86_REG_ES,
		"fs": uc.X86_REG_FS,
		"gs": uc.X86_REG_GS,
		"ss": uc.X86_REG_SS,

		/* // TODO: can't handle 80-bit regs
		"st0": uc.X86_REG_ST0,
		"st1": uc.X86_REG_ST0,
		"st2": uc.X86_REG_ST0,
		"st3": uc.X86_REG_ST0,
		"st4": uc.X86_REG_ST0,
		"st5": uc.X86_REG_ST0,
		"st6": uc.X86_REG_ST0,
		"st7": uc.X86_REG_ST0,
		*/
	},
	DefaultRegs: []string{
		"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
	},
	GdbXml: gdbXml,
}

func Wrmsr(u models.Usercorn, msr, value uint64) {
	u.RunAsm(
		0, "wrmsr",
		map[int]uint64{
			uc.X86_REG_RAX: value & 0xFFFFFFFF,
			uc.X86_REG_RDX: value >> 32 & 0xFFFFFFFF,
			uc.X86_REG_RCX: msr & 0xFFFFFFFF,
		}, nil,
	)
}

func Rdmsr(u models.Usercorn, msr uint64) uint64 {
	rcx, _ := u.RegRead(uc.X86_REG_RCX)
	rdx, _ := u.RegRead(uc.X86_REG_RDX)

	u.RunAsm(0, "rdmsr", map[int]uint64{uc.X86_REG_RAX: msr}, nil)
	ecx, _ := u.RegRead(uc.X86_REG_ECX)
	edx, _ := u.RegRead(uc.X86_REG_EDX)

	u.RegWrite(uc.X86_REG_RCX, rcx)
	u.RegWrite(uc.X86_REG_RDX, rdx)
	return (edx << 32) | (ecx & 0xFFFFFFFF)
}
