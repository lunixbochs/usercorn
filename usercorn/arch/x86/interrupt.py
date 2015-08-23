from unicorn.x86_const import *
import os
import sys

def syscall(cls):
    regs = [X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_RDX, X86_REG_ESI, X86_REG_EDI, X86_REG_EBP]
    num, a1, a2, a3, a4, a5, a6 = [cls.reg_read(r) for r in regs]
    ret = 0
    if num == 1: # SYS_exit
        sys.exit(a1)
    elif num == 2: # SYS_fork
        ret = os.fork()
    elif num == 3: # SYS_read
        tmp = os.read(a1, a3)
        cls.mem_write(a2, tmp + '\0')
        ret = len(tmp)
    elif num == 4: # SYS_write
        ret = os.write(a1, cls.mem_read(a2, a3))
    elif num == 5: # SYS_open
        ret = os.open(cls.mem_read_cstr(a1), a2, a3)
    elif num == 6: # SYS_close
        os.close(a1)
    elif num == 19: # SYS_lseek
        ret = os.lseek(a1, a2, a3)
    elif num == 90: # SYS_mmap
        ret = cls.mmap(a2, addr_hint=a1)
    elif num == 91: # SYS_munmap
        pass
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)
    cls.reg_write(X86_REG_EAX, ret)

def interrupt(cls, intno):
    if intno == 80:
        syscall(cls)
    else:
        pass
        # raise NotImplementedError('unhandled interrupt %d' % intno)
