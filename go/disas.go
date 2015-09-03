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
