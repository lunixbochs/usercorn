from unicorn.x86_const import *
import os
import sys

from usercorn import syscalls

SYSCALLS = {
    1: 'exit',
    2: 'fork',
    3: 'read',
    4: 'write',
    5: 'open',
    6: 'close',
    7: 'wait4',
    9: 'link',
    10: 'unlink',
    73: 'munmap',
    197: 'mmap',
    199: 'lseek',
}

def syscall(cls):
    esp = cls.reg_read(UC_X86_REG_ESP)
    num = cls.reg_read(UC_X86_REG_EAX)
    ret = syscalls.call(cls, SYSCALLS, num, syscalls.stack_args(cls))
    cls.reg_write(UC_X86_REG_EAX, ret)
    cls.reg_write(UC_X86_REG_ESP, esp)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
