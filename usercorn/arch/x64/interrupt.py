from unicorn.x86_const import *
import os
import sys

def syscall(cls):
    regs = [X86_REG_RAX, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_R10, X86_REG_R8, X86_REG_R9]
    num, a1, a2, a3, a4, a5, a6 = [cls.reg_read(r) for r in regs]
    ret = 0
    if num == 0: # SYS_read
        tmp = os.read(a1, a3)
        cls.mem_write(a2, tmp + '\0')
        ret = len(tmp)
    elif num == 1: # SYS_write
        ret = os.write(a1, cls.mem_read(a2, a3))
    elif num == 2: # SYS_open
        ret = os.open(cls.mem_read_cstr(a1), a2, a3)
    elif num == 3: # SYS_close
        os.close(a1)
    elif num == 8: # SYS_lseek
        ret = os.lseek(a1, a2, a3)
    elif num == 9: # SYS_mmap
        ret = cls.mmap(a2, addr_hint=a1)
    elif num == 11: # SYS_munmap
        pass
    elif num == 60: # SYS_exit
        sys.exit(a1)
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)
    cls.reg_write(X86_REG_RAX, ret)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
