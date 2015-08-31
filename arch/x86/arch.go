package x86

import (
    cs "github.com/bnagy/gapstone"
    uc "github.com/lunixbochs/unicorn"
    "fmt"
    "syscall"

    "../../models"
)

var Arch = &models.Arch{
	Bits:      32,
	Radare:    "x86",
	CS_ARCH:   cs.CS_ARCH_X86,
	CS_MODE:   cs.CS_MODE_32,
	UC_ARCH:   uc.UC_ARCH_X86,
	UC_MODE:   uc.UC_MODE_32,
	SP:        uc.UC_X86_REG_ESP,
	Syscall:   Syscall,
	Interrupt: Interrupt,
}

func Syscall(u models.Usercorn) {
    // TODO: handle errors or something
    var regs = []int{uc.UC_X86_REG_EBX, uc.UC_X86_REG_ECX, uc.UC_X86_REG_EDX, uc.UC_X86_REG_ESI, uc.UC_X86_REG_EDI, uc.UC_X86_REG_EBP}
    var args [6]uint64
    for i, r := range regs {
        n, _ := u.RegRead(r)
        args[i] = n
    }

    eax, _ := u.RegRead(uc.UC_X86_REG_EAX)
    var ret uint64
    switch eax {
    case 1: // exit
        syscall.Exit(int(args[0]))
    case 2: // fork
        // Go does not like fork
    case 3: // read
        tmp := make([]byte, args[2])
        n, _ := syscall.Read(int(args[0]), tmp)
        u.MemWrite(args[1], tmp[:n])
        ret = uint64(n)
    case 4: // write
        mem, _ := u.MemRead(args[1], args[2])
        n, _ := syscall.Write(int(args[0]), mem)
        ret = uint64(n)
    case 5: // open
        path, _ := u.MemReadStr(args[0])
        fd, _ := syscall.Open(path, int(args[1]), uint32(args[2]))
        ret = uint64(fd)
    case 6: // close
        syscall.Close(int(args[0]))
    case 19: // lseek
        off, _ := syscall.Seek(int(args[0]), int64(args[1]), int(args[2]))
        ret = uint64(off)
    case 91: // munmap
    case 192: // mmap
        addr, _ := u.Mmap(args[0], args[1])
        ret = uint64(addr)
    default:
        panic(fmt.Sprintf("unhandled syscall %d", eax))
    }
    u.RegWrite(uc.UC_X86_REG_EAX, ret)
}

func Interrupt(u models.Usercorn, intno uint32) {
    if intno == 0x80 {
        Syscall(u)
    }
}
