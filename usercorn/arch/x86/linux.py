from unicorn.x86_const import *
import os
import sys

from usercorn import syscalls

SYSCALLS = {
    1: ('exit', 1),
    2: ('fork', 0),
    3: ('read', 3),
    4: ('write', 3),
    5: ('open', 3), # variable length args?
    6: ('close', 1),
    9: ('link', 2),
    10: ('unlink', 1),
    19: ('lseek', 3),
    90: ('mmap', 6),
    91: ('munmap', 2),
    192: ('mmap', 6),
}

def syscall(cls):
    regs = [UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP]
    args = [cls.reg_read(r) for r in regs]
    def call(name, n):
        return getattr(syscalls, name)(cls, *args[:n]) or 0

    num = cls.reg_read(UC_X86_REG_EAX)
    params = SYSCALLS.get(num)
    if params:
        ret = call(*params)
        cls.reg_write(UC_X86_REG_EAX, ret)
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
