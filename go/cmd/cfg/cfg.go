package main

import (
	"fmt"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

type Block struct {
	u models.Usercorn

	Addr, Size uint64
}

func (b *Block) Print() {
	u := b.u
	u.Printf("[Block 0x%x-0x%x]\n", b.Addr, b.Addr+b.Size)
	dis, _ := u.Dis(b.Addr, b.Size, false)
	u.Printf("%s", dis)
	u.Println("")
}

type BacktrackEngine struct {
	u models.Usercorn
}

func (b *BacktrackEngine) Run() {}

func EmuCfg(u models.Usercorn, backtrack bool) map[uint64]*Block {
	u.Config().BlockSyscalls = true

	blocks := make(map[uint64]*Block)
	u.HookAdd(cpu.HOOK_BLOCK, func(_ cpu.Cpu, addr uint64, size uint32) {
		blocks[addr] = &Block{u, addr, uint64(size)}
	}, 1, 0)

	// TODO: instead of the below... support read-only filesystem operations, just nothing destructive?
	// like open, read, mmap
	// otherwise we won't be able to map a binary

	// automatically map unmapped pages (besides the zero page)
	u.HookAdd(cpu.HOOK_MEM_ERR, func(_ cpu.Cpu, errno int, addr uint64, size int, value int64) bool {
		if errno == cpu.MEM_UNMAPPED && addr > 0x1000 {
			align := addr & ^uint64(0xfff)
			u.MemMap(align, align+0x1000, cpu.PROT_ALL)
			return true
		}
		return false
	}, 1, 0)

	if backtrack {
		bt := &BacktrackEngine{u}
		bt.Run()
	} else {
		u.Gate().UnlockStopRelock()
	}
	return blocks
}

func StaticCfg() {
}

func CfgMain(u models.Usercorn, backtrack, json bool) error {
	blocks := EmuCfg(u, backtrack)
	fmt.Println("here", len(blocks))
	return nil
}
