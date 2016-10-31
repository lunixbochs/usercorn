package main

import (
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

type Block struct {
	u models.Usercorn

	Addr, Size uint64
}

func (b *Block) Print() {
	u := b.u
	u.Printf("[Block 0x%x-0x%x]\n", b.Addr, b.Addr+b.Size)
	dis, _ := u.Disas(b.Addr, b.Size, false)
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
	u.HookAdd(uc.HOOK_BLOCK, func(_ uc.Unicorn, addr uint64, size uint32) {
		blocks[addr] = &Block{u, addr, uint64(size)}
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
