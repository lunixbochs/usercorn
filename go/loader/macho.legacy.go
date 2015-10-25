package loader

import "debug/macho"

const machoCpuArch64 = 0x01000000

const (
	machoCpu386   macho.Cpu = macho.Cpu386
	machoCpuAmd64 macho.Cpu = macho.CpuAmd64
	machoCpuArm   macho.Cpu = 12
	machoCpuPpc   macho.Cpu = 18
	machoCpuPpc64 macho.Cpu = machoCpuPpc | machoCpuArch64
)
