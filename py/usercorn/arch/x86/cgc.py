from unicorn.x86_const import *
import os
import sys

def syscall(cls):
    regs = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP]
    num, a1, a2, a3, a4, a5, a6 = [cls.reg_read(r) for r in regs]
    ret = 0
    # _terminate
    if num == 1:
        sys.exit(a1)
    # transmit
    elif num == 2:
        n = os.write(a1, cls.mem_read(a2, a3))
        cls.mem_write(a4, cls.pack_addr(n))
    # receive
    elif num == 3: 
        tmp = os.read(a1, a3)
        cls.mem_write(a2, tmp)
        cls.mem_write(a4, cls.pack_addr(len(tmp)))
    # fdwait
    elif num == 4:
        pass
    # allocate
    elif num == 5:
        addr = cls.mmap(a1)
        cls.mem_write(a3, cls.pack_addr(addr))
    # deallocate
    elif num == 6:
        pass
    # random
    elif num == 7: 
        rnd = os.urandom(a2)
        cls.mem_write(a1, rnd)
        cls.mem_write(a3, cls.pack_addr(a2))
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)
    cls.reg_write(UC_X86_REG_EAX, ret)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
