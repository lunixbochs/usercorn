package models

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/lunixbochs/fvbommel-util/sortorder"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/models/cpu"
)

// platform interfaces
type Asm interface {
	Asm(asm string, addr uint64) ([]byte, error)
}
type Dis interface {
	Dis(mem []byte, addr uint64) ([]Ins, error)
}
type CpuBuilder interface {
	New() (cpu.Cpu, error)
}

type Reg struct {
	Enum    int
	Name    string
	Default bool
}

type RegVal struct {
	Reg
	Val uint64
}

type regList []Reg

func (r regList) Len() int      { return len(r) }
func (r regList) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r regList) Less(i, j int) bool {
	inum := strings.IndexAny(r[i].Name, "0123456789")
	jnum := strings.IndexAny(r[j].Name, "0123456789")
	if inum != -1 && jnum != -1 {
		return sortorder.NaturalLess(r[i].Name, r[j].Name)
	} else if inum == -1 && jnum != -1 {
		return true
	} else if jnum == -1 && inum != -1 {
		return false
	} else {
		return r[i].Name < r[j].Name
	}
}

type regMap map[string]int

func (r regMap) Items() regList {
	ret := make(regList, 0, len(r))
	for name, enum := range r {
		ret = append(ret, Reg{enum, name, false})
	}
	return ret
}

type Arch struct {
	Name   string
	Bits   int
	Radare string

	Cpu CpuBuilder
	Asm Asm
	Dis Dis

	PC     int
	SP     int
	OS     map[string]*OS
	Regs   regMap
	GdbXml string

	DefaultRegs []string

	regNames map[int]string
	// sorted for RegDump
	regList  regList
	regEnums []int

	regBatch *uc.RegBatch
}

func (a *Arch) String() string {
	return fmt.Sprintf("<Arch %s>", a.Name)
}

func (a *Arch) RegNames() map[int]string {
	if a.regNames == nil {
		a.regNames = make(map[int]string, len(a.Regs))
		for name, enum := range a.Regs {
			a.regNames[enum] = name
		}
	}
	return a.regNames
}

func (a *Arch) RegisterOS(os *OS) {
	if a.OS == nil {
		a.OS = make(map[string]*OS)
	}
	if _, ok := a.OS[os.Name]; ok {
		panic("Duplicate OS " + os.Name)
	}
	a.OS[os.Name] = os
}

func (a *Arch) getRegList() regList {
	if a.regList == nil {
		rl := a.Regs.Items()
		sort.Sort(rl)
		for i, reg := range rl {
			// O(N) but it's a small list and only searched once
			for _, match := range a.DefaultRegs {
				if reg.Name == match {
					rl[i].Default = true
					break
				}
			}
		}
		a.regList = rl
	}
	return a.regList
}

func (a *Arch) SmokeTest(t *testing.T) {
	u, err := a.Cpu.New()
	if err != nil {
		t.Fatal(err)
	}
	var testReg = func(name string, enum int) {
		if u.RegWrite(enum, 0x1000); err != nil {
			t.Fatal(err)
		}
		val, err := u.RegRead(enum)
		if err != nil {
			t.Fatal(err)
		}
		if val != 0x1000 {
			t.Fatal(a.Name + " failed to read/write register " + name)
		}
		// clear the register in case registers are aliased
		if u.RegWrite(enum, 0); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range a.getRegList() {
		if r.Default {
			testReg(r.Name, r.Enum)
		}
	}
	testReg("PC", a.PC)
	testReg("SP", a.SP)
}

type execTest struct {
	u          cpu.Cpu
	a          *Arch
	start, end uint64
	dis        string
}

func (t *execTest) Setup(asm string) error {
	base := uint64(0x1000)
	u, err := t.a.Cpu.New()
	if err != nil {
		return errors.Wrapf(err, "Arch<%s>.Cpu.New() failed", t.a.Name)
	}
	t.u = u
	shellcode, err := Assemble(asm, base, t.a)
	if err != nil {
		return errors.Wrap(err, "Assemble() failed")
	}
	dis, err := Disas(shellcode, base, t.a, true)
	if err != nil {
		return errors.Wrap(err, "Disas() failed")
	}
	t.dis = dis

	size := (uint64(len(shellcode)) + 0xfff) &^ 0xfff
	if err := u.MemMap(base, size, cpu.PROT_ALL); err != nil {
		return errors.Wrapf(err, "u.MemMap(%#x, %#x) failed", base, size)
	}
	if err := u.MemWrite(base, shellcode); err != nil {
		return errors.Wrapf(err, "u.MemWrite(%#x, [%d]byte) failed", base, size)
	}
	t.start = base
	t.end = base + uint64(len(shellcode))
	return nil
}

func (t *execTest) Run() error {
	if err := t.u.Start(t.start, t.end); err != nil {
		pc, _ := t.u.RegRead(t.a.PC)
		fmt.Fprintf(os.Stderr, "%s\n", t.dis)
		return errors.Wrapf(err, "u.Start(%#x, %#x) failed: [pc=%#x]", t.start, t.end, pc)
	}
	return nil
}

func (t *execTest) Close() {
	t.u.Close()
}

func (a *Arch) TestExec(t *testing.T, asm string) {
	test := &execTest{a: a}
	if err := test.Setup(asm); err != nil {
		t.Fatal(err)
	}
	if err := test.Run(); err != nil {
		t.Fatal(err)
	}
}

// TODO: bench with each set of hooks enabled? using sub-benchmarks
func (a *Arch) BenchExec(b *testing.B, asm string) {
	test := &execTest{a: a}
	if err := test.Setup(asm); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := test.Run(); err != nil {
			b.Fatal(err)
		}
	}
}

func (a *Arch) BenchRegs(b *testing.B) {
	u, err := a.Cpu.New()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := a.RegDumpFast(u); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.RegDumpFast(u); err != nil {
			b.Fatal(err)
		}
	}
}

func (a *Arch) RegEnums() []int {
	regList := a.getRegList()
	enums := make([]int, len(regList))
	for i, r := range regList {
		enums[i] = r.Enum
	}
	return enums
}

// FIXME: abstraction hack
func (a *Arch) RegDumpFast(c cpu.Cpu) ([]uint64, error) {
	// manual check for Unicorn because Cpu interface doesn't have RegBatch for now
	if u, ok := c.Backend().(uc.Unicorn); ok {
		if a.regBatch == nil {
			var err error
			enums := a.RegEnums()
			a.regBatch, err = uc.NewRegBatch(enums)
			if err != nil {
				return nil, err
			}
		}
		return a.regBatch.ReadFast(u)
	} else {
		enums := a.RegEnums()
		out := make([]uint64, len(enums))
		for i, e := range enums {
			val, err := c.RegRead(e)
			if err != nil {
				return nil, err
			}
			out[i] = val
		}
		return out, nil
	}
}

func (a *Arch) RegDump(u cpu.Cpu) ([]RegVal, error) {
	regList := a.getRegList()
	regs, err := a.RegDumpFast(u)
	if err != nil {
		return nil, err
	}
	ret := make([]RegVal, len(regList))
	for i, r := range regList {
		ret[i] = RegVal{r, regs[i]}
	}
	return ret, nil
}

type OS struct {
	Name      string
	Kernels   func(Usercorn) []interface{}
	Init      func(Usercorn, []string, []string) error
	Interrupt func(Usercorn, uint32)
}

func (o *OS) String() string {
	return fmt.Sprintf("<OS %s>", o.Name)
}
