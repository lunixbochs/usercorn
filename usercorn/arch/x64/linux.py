from unicorn.x86_const import *
import os
import sys

from .posix import syscall_args
from usercorn import syscalls

SYSCALLS = {
    0: ('read', 3),
    1: ('write', 3),
    2: ('open', 3),
    3: ('close', 1),
    8: ('lseek', 3),
    9: ('mmap', 6),
    11: ('munmap', 2),
    60: ('exit', 1),
}

def syscall(cls):
    num, args = syscall_args(cls)
    def call(name, n):
        return getattr(syscalls, name)(cls, *args[:n]) or 0

    params = SYSCALLS.get(num)
    if params:
        ret = call(*params)
        cls.reg_write(UC_X86_REG_RAX, ret)
    else:
        print 'Unsupported syscall:', num
        sys.exit(1)

def interrupt(cls, intno):
    if intno == 0x80:
        syscall(cls)
    else:
        raise NotImplementedError('unhandled interrupt %d' % intno)
