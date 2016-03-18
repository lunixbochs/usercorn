package arm

import (
	"github.com/lunixbochs/usercorn/go/models"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func enterUsermode(u models.Usercorn) error {
	// place CPU into user mode
	modeSwitch := []byte{
		0x00, 0x00, 0x0f, 0xe1, // mrs r0, cpsr
		0x1f, 0x00, 0xc0, 0xe3, // bic r0, r0, $0x1f
		0x10, 0x00, 0x80, 0xe3, // orr r0, r0, $0x10
		0x00, 0xf0, 0x69, 0xe1, // msr spsr, r0
		0x0e, 0xf0, 0xb0, 0xe1, // movs pc, lr
	}
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
