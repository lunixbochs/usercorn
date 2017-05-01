package mips

import (
	"crypto/rand"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"syscall"
	"time"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/loader"
	"github.com/lunixbochs/usercorn/go/models"
)

var reesesSysNum = map[int]string{
	1:  "exit",
	3:  "read",
	4:  "write",
	5:  "rand",
	13: "time",
	14: "malloc",
}

type ReesesKernel struct {
	*co.KernelBase
}

func (k *ReesesKernel) Exit(code int) {
	k.U.Exit(models.ExitStatus(code))
}

func (k *ReesesKernel) Write(fd co.Fd, buf co.Buf, size co.Len) int {
	if fd == 0 {
		fd = 1
	}
	mem, err := k.U.MemRead(buf.Addr, uint64(size))
	if err != nil {
		return -1 // FIXME
	}
	n, err := syscall.Write(int(fd), mem)
	if err != nil {
		return -1 // FIXME
	}
	return n
}

func (k *ReesesKernel) Read(fd co.Fd, buf co.Obuf, size co.Len) int {
	tmp := make([]byte, size)
	n, err := syscall.Read(int(fd), tmp)
	if err != nil {
		return -1 // FIXME
	}
	if err := buf.Pack(tmp[:n]); err != nil {
		return -1 // FIXME
	}
	return n
}

func (k *ReesesKernel) Mmap(size uint32, executable int32) uint32 {
	// round up to nearest page
	size = (size + 0x1000) & ^uint32(0x1000-1)
	mmap, _ := k.U.Mmap(0, uint64(size))
	mmap.Desc = "heap"
	if executable != 0 {
		k.U.MemProtect(mmap.Addr, mmap.Size, uc.PROT_ALL)
	}
	return uint32(mmap.Addr)
}

func (k *ReesesKernel) Time() uint32 {
	return uint32(time.Now().Unix())
}

func (k *ReesesKernel) Random(buf co.Obuf, size uint32) uint32 {
	tmp := make([]byte, size)
	n, _ := rand.Read(tmp)
	tmp = tmp[:n]
	buf.Pack(tmp)
	return uint32(n)
}

var regNames = []string{
	"at", "v0", "v1", "a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9",
	"s0", "s1", "s2", "s3", "s4", "s5", "s6",
	"s7", "s8", "k0", "k1", "gp", "sp", "ra",
}

func ReesesInit(u models.Usercorn, args, env []string) error {
	loader := u.Loader().(*loader.ReesesLoader)
	for _, reg := range loader.Regs {
		if reg.Num > 0 && int(reg.Num) < len(regNames) {
			name := regNames[int(reg.Num)]
			enum := u.Arch().Regs[name]
			u.RegWrite(enum, uint64(reg.Val))
		}
	}
	return nil
}

func ReesesSyscall(u models.Usercorn) {
	num, _ := u.RegRead(uc.MIPS_REG_V0)
	if num >= 4000 && num <= 4014 {
		num -= 4000
		name, _ := reesesSysNum[int(num)]
		ret, _ := u.Syscall(int(num), name, co.RegArgs(u, LinuxRegs))
		// looks like errors are passed back in $a3
		if int64(ret) < 0 {
			u.RegWrite(uc.MIPS_REG_A3, 1)
		} else {
			u.RegWrite(uc.MIPS_REG_A3, 0)
		}
		u.RegWrite(uc.MIPS_REG_V0, ret)
	} else {
		u.Printf("Invalid syscall: %d (%d)\n", num, num-4000)
	}
}

func ReesesInterrupt(u models.Usercorn, cause uint32) {
	intno := (cause >> 1) & 15
	if intno == 8 {
		ReesesSyscall(u)
		return
	} else if intno == 10 {
		// reserved instruction
		pc, _ := u.RegRead(u.Arch().PC)
		ins, _ := u.MemRead(pc, 4)
		fmt.Printf("Int 10 (reserved instruction) 0x%x: %x. Skipping!\n", pc, ins)
		u.Restart(func(u models.Usercorn, err error) error {
			u.RegWrite(u.Arch().PC, pc+4)
			return nil
		})
	} else {
		panic(fmt.Sprintf("unhandled MIPS interrupt %d", intno))
	}
}

func ReesesKernels(u models.Usercorn) []interface{} {
	kernel := &ReesesKernel{&co.KernelBase{}}
	return []interface{}{kernel}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "reeses",
		Init:      ReesesInit,
		Interrupt: ReesesInterrupt,
		Kernels:   ReesesKernels,
	})
}
