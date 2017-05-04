package arm

import (
	cs "github.com/bnagy/gapstone"
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

var Arch = &models.Arch{
	Bits:    32,
	Radare:  "arm",
	CS_ARCH: cs.CS_ARCH_ARM,
	CS_MODE: cs.CS_MODE_ARM,
	KS_ARCH: ks.ARCH_ARM,
	KS_MODE: ks.MODE_ARM,
	UC_ARCH: uc.ARCH_ARM,
	UC_MODE: uc.MODE_ARM,
	PC:      uc.ARM_REG_PC,
	SP:      uc.ARM_REG_SP,
	Regs: map[string]int{
		"r0":  uc.ARM_REG_R0,
		"r1":  uc.ARM_REG_R1,
		"r2":  uc.ARM_REG_R2,
		"r3":  uc.ARM_REG_R3,
		"r4":  uc.ARM_REG_R4,
		"r5":  uc.ARM_REG_R5,
		"r6":  uc.ARM_REG_R6,
		"r7":  uc.ARM_REG_R7,
		"r8":  uc.ARM_REG_R8,
		"r9":  uc.ARM_REG_R9,
		"r10": uc.ARM_REG_R10,
		"r11": uc.ARM_REG_R11,
		"r12": uc.ARM_REG_R12,
		"lr":  uc.ARM_REG_LR,
		"sp":  uc.ARM_REG_SP,
		"pc":  uc.ARM_REG_PC,
	},
	DefaultRegs: []string{
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
		"r9", "r10", "r11", "r12",
	},
}

func EnterUsermode(u models.Usercorn) error {
	// move CPU from System to User mode
	modeSwitchAsm := `
        mrs r0, cpsr
        bic r0, r0, $0x1f
        orr r0, r0, $0x10
        msr cpsr_c, r0
    `
	modeSwitch, err := u.Assemble(modeSwitchAsm, 0)
	if err != nil {
		return err
	}
	// this is manually mapped instead of using RunShellcode() so
	// the link register will be set to exit the emulator correctly
	mmap, err := u.Mmap(0, uint64(len(modeSwitch)))
	if err != nil {
		return err
	}
	defer u.MemUnmap(mmap.Addr, mmap.Size)
	end := mmap.Addr + uint64(len(modeSwitch))
	return u.RunShellcodeMapped(mmap, modeSwitch,
		map[int]uint64{uc.ARM_REG_LR: end},
		[]int{uc.ARM_REG_R0, uc.ARM_REG_LR, uc.ARM_REG_SP},
	)
}

func EnableFPU(u models.Usercorn) error {
	val, err := u.RegRead(uc.ARM_REG_C1_C0_2)
	if err != nil {
		return err
	}
	if err = u.RegWrite(uc.ARM_REG_C1_C0_2, val|(0xf<<20)); err != nil {
		return err
	}
	return u.RegWrite(uc.ARM_REG_FPEXC, 0x40000000)
}
