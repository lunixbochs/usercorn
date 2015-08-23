from unicorn.x86_const import *
import os
import sys

def syscall(cls):
    regs = [X86_REG_RAX, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_R10, X86_REG_R8, X86_REG_R9]
    num, a1, a2, a3, a4, a5, a6 = [cls.reg_read(r) for r in regs]
    ret = 0
    if num == -1:
        pass
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)
    cls.reg_write(X86_REG_RAX, ret)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
