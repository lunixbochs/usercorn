package main

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models"
)

type Transaction struct {
	ctx uc.Context
	u   models.Usercorn
	hh  uc.Hook

	memWrites map[uint64]byte
}

func NewTransaction(u models.Usercorn) *Transaction {
	ctx, _ := u.ContextSave(nil)
	memWrites := make(map[uint64]byte)
	hh, _ := u.HookAdd(uc.HOOK_MEM_WRITE, func(_ uc.Unicorn, addr uint64, size uint32) {
		data, _ := u.MemRead(addr, uint64(size))
		for i, b := range data {
			pos := addr + uint64(i)
			if _, ok := memWrites[pos]; !ok {
				memWrites[pos] = b
			}
		}
	}, 1, 0)
	return &Transaction{
		u:   u,
		ctx: ctx,
		hh:  hh,

		memWrites: memWrites,
	}
}

func (t *Transaction) Rewind() {
	t.u.ContextRestore(t.ctx)
	for addr, b := range t.memWrites {
		t.u.MemWrite(addr, []byte{b})
	}
}

func (t *Transaction) Discard() {
	t.u.HookDel(t.hh)
}
