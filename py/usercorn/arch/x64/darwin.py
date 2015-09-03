from unicorn.x86_const import *
import os
import sys

from .posix import syscall_args
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
    num, args = syscall_args(cls)
    num -= 0x2000000
    ret = syscalls.call(cls, SYSCALLS, num, lambda n: args[:n])
    cls.reg_write(UC_X86_REG_RAX, ret)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
