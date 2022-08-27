package bpf

import (
	"github.com/lunixbochs/usercorn/go/cpu/bpf"
	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Name: "bpf",
	Bits: 32,

	Cpu: &bpf.Builder{},
	Dis: &bpf.Dis{},
	Asm: nil,

	PC: bpf.PC,
	SP: -1, // TODO: There is no stack pointer. How to handle?
	Regs: map[string]int{
		"M0":  bpf.M0,
		"M1":  bpf.M1,
		"M2":  bpf.M2,
		"M3":  bpf.M3,
		"M4":  bpf.M4,
		"M5":  bpf.M5,
		"M6":  bpf.M6,
		"M7":  bpf.M7,
		"M8":  bpf.M8,
		"M9":  bpf.M9,
		"M10": bpf.M10,
		"M11": bpf.M11,
		"M12": bpf.M12,
		"M13": bpf.M13,
		"M14": bpf.M14,
		"M15": bpf.M15,
		"A":   bpf.A,
		"X":   bpf.X,
		"PC":  bpf.PC,
	},

	DefaultRegs: []string{
		"M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9",
		"M10", "M11", "M12", "M13", "M14", "M15", "A", "X"},
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:    "noos",
		Kernels: func(_ models.Usercorn) []interface{} { return nil },
		Init: func(u models.Usercorn, _, _ []string) error {
			u.SetEntry(0x80000000)
			return nil
		},
		Interrupt: func(_ models.Usercorn, _ uint32) {},
	})
}
