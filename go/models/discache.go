package models

import (
	"bytes"
	"sync"
)

type DiscacheEntry struct {
	Addr uint64
	Mem  []byte
	Dis  []Ins
}

type Discache struct {
	sync.RWMutex
	cache map[uint64]*DiscacheEntry
}

func NewDiscache() *Discache {
	return &Discache{cache: make(map[uint64]*DiscacheEntry)}
}

func (d *Discache) Get(addr uint64, mem []byte) *DiscacheEntry {
	d.RLock()
	if ent, ok := d.cache[addr]; ok {
		if bytes.Equal(mem, ent.Mem) {
			d.RUnlock()
			return ent
		}
	}
	d.RUnlock()
	return nil
}

func (d *Discache) Put(addr uint64, mem []byte, dis []Ins) {
	d.Lock()
	d.cache[addr] = &DiscacheEntry{
		Addr: addr,
		Mem:  mem,
		Dis:  dis,
	}
	d.Unlock()
}
