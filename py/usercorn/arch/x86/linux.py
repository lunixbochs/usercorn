from unicorn.x86_const import *
import os
import sys

from usercorn import syscalls

SYSCALLS = {
    1: 'exit',
    2: 'fork',
    3: 'read',
    4: 'write',
    5: 'open', # variable length args?
    6: 'close',
    9: 'link',
    10: 'unlink',
    19: 'lseek',
    90: 'mmap',
    91: 'munmap',
    192: 'mmap',
}

def syscall(cls):
    regs = [UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP]
    args = [cls.reg_read(r) for r in regs]
    num = cls.reg_read(UC_X86_REG_EAX)
    ret = syscalls.call(cls, SYSCALLS, num, lambda n: args[:n])
    cls.reg_write(UC_X86_REG_EAX, ret)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
