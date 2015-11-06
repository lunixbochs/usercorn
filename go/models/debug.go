package models

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/bnagy/gapstone"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strings"
)

var demangleRe = regexp.MustCompile(`^[^(]+`)

func Demangle(name string) string {
	if strings.HasPrefix(name, "__Z") {
		name = name[1:]
	} else if !strings.HasPrefix(name, "_Z") {
		return name
	}
	cmd := exec.Command("c++filt", "-n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return name
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return name
	}
	if err = cmd.Start(); err != nil {
		fmt.Println("cmd error", err)
		return name
	}
	stdin.Write([]byte(name + "\n"))
	stdin.Close()
	out, err := ioutil.ReadAll(stdout)
	out = bytes.Trim(out, "\t\r\n ")
	if err != nil || len(out) == 0 {
		return name
	}
	cmd.Wait()
	out = demangleRe.FindSubmatch(out)[0]
	return string(out)
}

var discache = make(map[string]string)

func Disas(mem []byte, addr uint64, arch *Arch, pad ...int) (string, error) {
	cacheKey := string(mem)
	if len(mem) == 0 {
		return "", nil
	}
	var asm []gapstone.Instruction
	if cached, ok := discache[cacheKey]; ok {
		return cached, nil
	}
	engine, err := gapstone.New(arch.CS_ARCH, arch.CS_MODE)
	if err != nil {
		return "", err
	}
	defer engine.Close()
	asm, err = engine.Disasm(mem, addr, 0)
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
	ret := strings.Join(out, "\n")
	discache[cacheKey] = ret
	return ret, nil
}

func HexDump(base uint64, mem []byte, bits int) []string {
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
	bsz := bits / 8
	hexFmt := fmt.Sprintf("0x%%0%dx:", bsz*2)
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
				end := (j + 1) * bsz
				var block []byte
				if end > len(memLine) {
					pad := bytes.Repeat([]byte{0}, end-len(memLine))
					block = append(memLine[j*bsz:], pad...)
				} else {
					block = memLine[j*bsz : end]
				}
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
	return out
}
