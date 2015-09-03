from unicorn.x86_const import *
import os
import sys

from .posix import syscall_args
from usercorn import syscalls

SYSCALLS = {
    0: 'read',
    1: 'write',
    2: 'open',
    3: 'close',
    8: 'lseek',
    9: 'mmap',
    11: 'munmap',
    60: 'exit',
}

def syscall(cls):
    num, args = syscall_args(cls)
    ret = syscalls.call(cls, SYSCALLS, num, lambda n: args[:n])
    cls.reg_write(UC_X86_REG_RAX, ret)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
