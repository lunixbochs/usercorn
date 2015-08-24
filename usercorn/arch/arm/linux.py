from unicorn.arm_const import *
import os
import sys

def syscall(cls):
    # regs = [X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, X86_REG_ESI, X86_REG_EDI, X86_REG_EBP]
    # num, a1, a2, a3, a4, a5, a6 = [cls.reg_read(r) for r in regs]
    ret = 0
    if num == -1:
        pass
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)
    # cls.reg_write(UC_X86_REG_EAX, ret)

def interrupt(cls, intno):
    if intno == 0:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
