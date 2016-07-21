package x86

import (
	"crypto/rand"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/native"
)

var cgcSysNum = map[int]string{
	1: "_terminate",
	2: "transmit",
	3: "receive",
	4: "fdwait",
	5: "allocate",
	6: "deallocate",
	7: "random",
}

type CgcKernel struct {
	*co.KernelBase
}

func (k *CgcKernel) Literal_terminate(code int) {
	k.U.Exit(models.ExitStatus(code))
}

func (k *CgcKernel) Transmit(fd co.Fd, buf co.Buf, size co.Len, ret co.Obuf) int {
	mem, _ := k.U.MemRead(buf.Addr, uint64(size))
	n, err := syscall.Write(int(fd), mem)
	if err != nil {
		return -1 // FIXME
	}
	ret.Pack(int32(n))
	return 0
}

func (k *CgcKernel) Receive(fd co.Fd, buf co.Obuf, size co.Len, ret co.Obuf) int {
	tmp := make([]byte, size)
	n, err := syscall.Read(int(fd), tmp)
	if err != nil {
		return -1 // FIXME
	}
	buf.Pack(tmp[:n])
	ret.Pack(int32(n))
	return 0
}

func (k *CgcKernel) Fdwait(nfds int, reads, writes, timeoutBuf co.Buf, readyFds co.Obuf) int {
	var readSet, writeSet *native.Fdset32
	var timeout native.Timespec
	reads.Unpack(&readSet)
	writes.Unpack(&writeSet)
	timeoutBuf.Unpack(&timeout)

	readNative := readSet.Native()
	writeNative := writeSet.Native()

	n, err := native.Select(nfds, readNative, writeNative, &timeout)
	if err != nil {
		return -1 // FIXME?
	} else {
		readyFds.Pack(int32(n))
	}
	return 0
}

func (k *CgcKernel) Allocate(size uint32, executable int32, ret co.Obuf) int {
	// round up to nearest page
	size = (size + 0x1000) & ^uint32(0x1000-1)
	mmap, _ := k.U.Mmap(0, uint64(size))
	mmap.Desc = "heap"
	if executable != 0 {
		k.U.MemProtect(mmap.Addr, mmap.Size, uc.PROT_ALL)
	}
	ret.Pack(uint32(mmap.Addr))
	return 0
}

func (k *CgcKernel) Deallocate(addr, size uint32) int {
	// addr must be multiple of page size
	if addr&(0x1000-1) > 0 {
		return -1 // FIXME
	}
	// all pages containing a part of the range are unmapped
	var pages []*models.Mmap
	for _, mmap := range k.U.Mappings() {
		// does addr overlap mapping?
		if (uint64(addr) >= mmap.Addr && uint64(addr) < mmap.Addr+mmap.Size) ||
			(uint64(addr) < mmap.Addr && uint64(addr+size) > mmap.Addr) {
			pages = append(pages, mmap)
		}
	}
	for _, page := range pages {
		k.U.MemUnmap(page.Addr, page.Size)
	}
	return 0
}

func (k *CgcKernel) Random(buf co.Obuf, size uint32, ret co.Obuf) {
	tmp := make([]byte, size)
	n, _ := rand.Read(tmp)
	tmp = tmp[:n]
	buf.Pack(tmp)
	ret.Pack(uint32(n))
}

func CgcInit(u models.Usercorn, args, env []string) error {
	// TODO: does CGC even specify argv?
	// TODO: also, I seem to remember something about mapping in 16kb of random data
	secretPage := uint64(0x4347c000)
	if err := u.MemMap(secretPage, 0x1000); err != nil {
		return err
	}
	tmp := make([]byte, 0x1000)
	if _, err := rand.Read(tmp); err != nil {
		return err
	}
	if err := u.MemWrite(secretPage, tmp); err != nil {
		return err
	}

	for _, m := range u.Mappings() {
		if m.Desc == "stack" {
			u.MemUnmap(m.Addr, m.Size)
			break
		}
	}
	base := uint64(0xbaaab000 - 0x800000)
	if err := u.MemMapProt(base, 0x800000, uc.PROT_ALL); err != nil {
		return err
	}
	for _, m := range u.Mappings() {
		if m.Addr == base {
			m.Desc = "stack"
			break
		}
	}
	u.RegWrite(u.Arch().SP, 0xbaaaaffc)
	u.SetStackBase(base)
	return nil
}

func CgcSyscall(u models.Usercorn) {
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	name, _ := cgcSysNum[int(eax)]
	ret, _ := u.Syscall(int(eax), name, co.RegArgs(u, LinuxRegs))
	u.RegWrite(uc.X86_REG_EAX, ret)
}

func CgcInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		CgcSyscall(u)
	}
}

func CgcKernels(u models.Usercorn) []interface{} {
	kernel := &CgcKernel{&co.KernelBase{}}
	return []interface{}{kernel}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "cgc",
		Init:      CgcInit,
		Interrupt: CgcInterrupt,
		Kernels:   CgcKernels,
	})
}
