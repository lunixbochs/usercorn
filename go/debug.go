package main

import (
	"encoding/hex"
	"fmt"
	"github.com/bnagy/gapstone"
	"strings"

	"./models"
)

func Disas(mem []byte, addr uint64, arch *models.Arch, pad ...int) (string, error) {
	if len(mem) == 0 {
		return "", nil
	}
	engine, err := gapstone.New(arch.CS_ARCH, arch.CS_MODE)
	if err != nil {
		return "", err
	}
	defer engine.Close()
	asm, err := engine.Disasm(mem, addr, 0)
	if err != nil {
		return "", err
	}
	var width uint
	if len(pad) > 0 {
		width = uint(pad[0])
	}
	for _, insn := range asm {
		if insn.Size > width {
			width = insn.Size
		}
	}
	var out []string
	for _, insn := range asm {
		pad := strings.Repeat(" ", int(width-insn.Size)*2)
		data := pad + hex.EncodeToString(insn.Bytes)
		out = append(out, fmt.Sprintf("0x%x: %s %s %s", insn.Address, data, insn.Mnemonic, insn.OpStr))
	}
	return strings.Join(out, "\n"), nil
}

func HexDump(base uint64, mem []byte, arch *models.Arch) string {
	var clean = func(p []byte) string {
		o := make([]byte, len(p))
		for i, c := range p {
			if c >= 0x20 && c <= 0x7e {
				o[i] = c
			} else {
				o[i] = '.'
			}
		}
		return string(o)
	}
	bsz := arch.Bits / 8
	hexLen := len(fmt.Sprintf("%x", (uint64(len(mem)) + base)))
	hexFmt := fmt.Sprintf("0x%%0%dx:", hexLen)
	padBlock := strings.Repeat(" ", bsz*2)
	padTail := strings.Repeat(" ", bsz)

	width := 80
	addrSize := bsz*2 + 4
	blockCount := ((width - addrSize) * 3 / 4) / ((bsz + 1) * 2)
	lineSize := blockCount * bsz
	var out []string
	blocks := make([]string, blockCount)
	tail := make([]string, blockCount)
	for i := 0; i < len(mem); i += lineSize {
		memLine := mem[i:]
		for j := 0; j < blockCount; j++ {
			if j*bsz < len(memLine) {
				block := memLine[j*bsz : (j+1)*bsz]
				blocks[j] = hex.EncodeToString(block)
				tail[j] = clean(block)
			} else {
				blocks[j] = padBlock
				tail[j] = padTail
			}
		}
		line := []string{fmt.Sprintf(hexFmt, base+uint64(i))}
		line = append(line, strings.Join(blocks, " "))
		line = append(line, fmt.Sprintf("[%s]", strings.Join(tail, " ")))
		out = append(out, strings.Join(line, " "))
	}
	return strings.Join(out, "\n")
}
