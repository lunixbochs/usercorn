package models

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/bnagy/gapstone"
	ks "github.com/keystone-engine/keystone/bindings/go/keystone"
)

var demangleRe = regexp.MustCompile(`^[^(]+`)
var demangleCache = make(map[string]string)
var demangleLock sync.RWMutex

func demangleMiss(name string) string {
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
		fmt.Fprintf(os.Stderr, "cmd error", err)
		return name
	}
	stdin.Write([]byte(name + "\n"))
	stdin.Close()
	out, err := ioutil.ReadAll(stdout)
	out = bytes.Trim(out, "\t\r\n ")
	result := name
	if err != nil || len(out) == 0 {
		return name
	}
	cmd.Wait()
	out = demangleRe.FindSubmatch(out)[0]
	result = string(out)
	return result
}

func Demangle(name string) string {
	demangleLock.RLock()
	if hit, ok := demangleCache[name]; ok {
		demangleLock.RUnlock()
		return hit
	}
	demangleLock.RUnlock()
	result := demangleMiss(name)
	demangleLock.Lock()
	demangleCache[name] = result
	demangleLock.Unlock()
	return result
}

func Assemble(asm string, addr uint64, arch *Arch) ([]byte, error) {
	if arch.ks == nil {
		engine, err := ks.New(arch.KS_ARCH, arch.KS_MODE)
		if err != nil {
			return nil, err
		}
		arch.ks = engine
	}
	out, _, ok := arch.ks.Assemble(asm, addr)
	if !ok {
		return nil, arch.ks.LastError()
	}
	return out, nil
}

var discache = make(map[string]string)
var discacheLock sync.RWMutex

func Disas(mem []byte, addr uint64, arch *Arch, pad ...int) (string, error) {
	var asm []gapstone.Instruction
	cacheKey := fmt.Sprintf("%d|%s", addr, mem)
	if len(mem) == 0 {
		return "", nil
	}
	discacheLock.RLock()
	if cached, ok := discache[cacheKey]; ok {
		discacheLock.RUnlock()
		return cached, nil
	}
	discacheLock.RUnlock()
	if arch.cs == nil {
		engine, err := gapstone.New(arch.CS_ARCH, arch.CS_MODE)
		if err != nil {
			return "", err
		}
		arch.cs = &engine
	}
	asm, err := arch.cs.Disasm(mem, addr, 0)
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
	discacheLock.Lock()
	discache[cacheKey] = ret
	discacheLock.Unlock()
	return ret, nil
}

func Repr(p []byte, strsize int) string {
	trunc := false
	if len(p) > strsize && strsize > 0 {
		// factor quotes into strsize
		strsize -= 2
		p = p[:strsize-3]
		trunc = true
	}
	tmp := make([]byte, 0, len(p))
	for _, b := range p {
		if b >= 0x20 && b <= 0x7e {
			tmp = append(tmp, b)
		} else {
			var repr string
			switch b {
			case 0:
				repr = "\\0"
			case '\b':
				repr = "\\b"
			case '\r':
				repr = "\\r"
			case '\n':
				repr = "\\n"
			case '\t':
				repr = "\\t"
			default:
				repr = fmt.Sprintf("\\x%02x", b)
			}
			if strsize > 0 && len(tmp)+len(repr) <= strsize {
				tmp = append(tmp, repr...)
			}
		}
	}
	out := string(tmp)
	if strsize > 0 && len(out) > strsize {
		out = string(tmp[:strsize-3])
		trunc = true
	}
	if trunc {
		return "\"" + out + "\"..."
	}
	return "\"" + out + "\""
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
					block = memLine[j*bsz:]
				} else {
					block = memLine[j*bsz : end]
				}
				blocks[j] = hex.EncodeToString(block)
				tail[j] = clean(block)
				// if block was too short, pad with spaces
				if end > len(memLine) {
					pad := end - len(memLine)
					blocks[j] += strings.Repeat("  ", pad)
					tail[j] += strings.Repeat(" ", pad)
				}
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
