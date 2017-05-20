package ndh

import (
	"encoding/binary"
	"github.com/pkg/errors"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Builder struct{}

func (b *Builder) New() (cpu.Cpu, error) {
	c := &NdhCpu{
		Regs: cpu.NewRegs(16, []int{
			R0, R1, R2, R3, R4, R5, R6, R7,
			BP, SP, PC,
			ZF, AF, BF,
		}),
		Mem: cpu.NewMem(16, binary.LittleEndian),
	}
	c.Hooks = cpu.NewHooks(c, c.Mem)
	return c, nil
}

type NdhCpu struct {
	*cpu.Hooks
	*cpu.Regs
	*cpu.Mem
}

func (n *NdhCpu) Start(begin, until uint64) error {
	return errors.New("I don't work")
}

func (n *NdhCpu) Stop() error {
	return nil
}

func (n *NdhCpu) Close() error {
	return nil
}

func (n *NdhCpu) Backend() interface{} {
	return n
}
