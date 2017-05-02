package arm

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

func enterUsermode(u models.Usercorn) error {
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
	err = u.RunShellcodeMapped(mmap, modeSwitch,
		map[int]uint64{uc.ARM_REG_LR: end},
		[]int{uc.ARM_REG_R0, uc.ARM_REG_LR, uc.ARM_REG_SP},
	)
	return err
}
