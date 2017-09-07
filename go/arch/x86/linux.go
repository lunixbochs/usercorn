package x86

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/linux"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
)

const A_PRESENT = 0x80
const A_DATA = 0x10
const A_EXEC = 0x8
const A_DATA_WRITABLE = 0x2
const A_CODE_READABLE = 0x2
const A_PRIV_3 = 0x60
const A_PRIV_0 = 0x0
const A_CODE = 0x18
const A_DIR_CON_BIT = 0x4
const F_PROT_32 = 0x4
const S_GDT = 0x0
const S_PRIV_0 = 0x0
const S_PRIV_3 = 0x3
const GDT_ENTRY_SIZE = 0x8

var LinuxRegs = []int{uc.X86_REG_EBX, uc.X86_REG_ECX, uc.X86_REG_EDX, uc.X86_REG_ESI, uc.X86_REG_EDI, uc.X86_REG_EBP}

type LinuxKernel struct {
	*linux.LinuxKernel
	gdt *models.Mmap
}

var socketCallMap = map[int]string{
	1:  "socket",
	2:  "bind",
	3:  "connect",
	4:  "listen",
	5:  "accept",
	6:  "getsockname",
	7:  "getpeername",
	8:  "socketpair",
	9:  "send",
	10: "recv",
	11: "sendto",
	12: "recvfrom",
	13: "shutdown",
	14: "setsockopt",
	15: "getsockopt",
	16: "sendmsg",
	17: "recvmsg",
	18: "accept4",
}

func createSelector(idx uint32, flags uint32) uint64 {
	ret := flags
	ret |= idx << 3
	return uint64(ret)
}

// TODO: move this to arch.go or something
func (k *LinuxKernel) gdtWrite(sel, base, limit, access, flags uint32) {
	var entry uint64
	// set default access bits
	access |= 1 << 7
	if limit > 0xfffff {
		// set page granularity
		limit >>= 12
		flags |= 8
	}
	entry |= uint64(limit) & 0xFFFF
	entry |= ((uint64(limit) >> 16) & 0xF) << 48
	entry |= (uint64(base) & 0xFFFFFF) << 16
	entry |= (uint64(base>>24) & 0xFF) << 56
	entry |= (uint64(access) & 0xFF) << 40
	entry |= (uint64(flags) & 0xFF) << 52

	if k.gdt == nil {
		k.gdt, _ = k.U.Mmap(0, 0x1000)
		gdt := uc.X86Mmr{
			Base:  k.gdt.Addr,
			Limit: 31*8 - 1,
		}
		k.U.RegWriteMmr(uc.X86_REG_GDTR, &gdt)
	}
	// this is fragile but we only call it once below in SetThreadArea
	s := k.U.StrucAt(k.gdt.Addr + uint64(sel)*8)
	s.Pack(entry)
}

func (k *LinuxKernel) Socketcall(index int, params co.Buf) uint64 {
	if name, ok := socketCallMap[index]; ok {
		if sys := co.Lookup(k.U, k, name); sys != nil {
			rawArgs := make([]uint32, len(sys.In))
			if err := params.Unpack(rawArgs); err != nil {
				return posix.UINT64_MAX
			}
			args := make([]uint64, len(rawArgs))
			for i, v := range rawArgs {
				args[i] = uint64(v)
			}
			return sys.Call(args)
		}
	}
	return posix.UINT64_MAX // FIXME
}

func (k *LinuxKernel) SetThreadArea(addr uint64) int {
	s := k.U.StrucAt(addr)
	var uaddr, limit uint32
	s.Unpack(&uaddr) // burn one
	s.Unpack(&uaddr, &limit)

	k.gdtWrite(4, uaddr, limit, (A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT), F_PROT_32)
	k.U.RegWrite(uc.X86_REG_GS, createSelector(4, (S_GDT|S_PRIV_3)))
	k.U.StrucAt(addr).Pack(uint64(4))
	return 0
}

func (k *LinuxKernel) setupGdt() {
	k.gdtWrite(1, 0, 0xffffff00, (A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT), F_PROT_32) // code
	k.gdtWrite(2, 0, 0xffffff00, (A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT), F_PROT_32) // data
	k.gdtWrite(3, 0, 0xffffff00, (A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0), F_PROT_32)                 // stack
	k.U.RegWrite(uc.X86_REG_CS, createSelector(1, (S_GDT|S_PRIV_0)))
	k.U.RegWrite(uc.X86_REG_DS, createSelector(2, (S_GDT|S_PRIV_0)))
	k.U.RegWrite(uc.X86_REG_SS, createSelector(3, (S_GDT|S_PRIV_0)))
}

func LinuxKernels(u models.Usercorn) []interface{} {
	kernel := &LinuxKernel{LinuxKernel: linux.NewKernel()}
	kernel.U = u // hasn't been set by now
	kernel.setupGdt()
	return []interface{}{kernel}
}

func LinuxSyscall(u models.Usercorn) {
	// TODO: handle errors or something
	eax, _ := u.RegRead(uc.X86_REG_EAX)
	name, _ := num.Linux_x86[int(eax)]
	ret, _ := u.Syscall(int(eax), name, co.RegArgs(u, LinuxRegs))
	u.RegWrite(uc.X86_REG_EAX, ret)
}

func LinuxInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		LinuxSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{
		Name:      "linux",
		Kernels:   LinuxKernels,
		Init:      linux.StackInit,
		Interrupt: LinuxInterrupt,
	})
}
