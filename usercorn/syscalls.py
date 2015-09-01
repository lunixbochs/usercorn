import os
import sys

def exit(cls, n):
    sys.exit(n)

def fork(cls):
    return os.fork()

def read(cls, a1, a2, a3):
    tmp = os.read(a1, a3)
    cls.mem_write(a2, tmp)
    return len(tmp)

def write(cls, a1, a2, a3):
    return os.write(a1, cls.mem_read(a2, a3))

def open(cls, a1, a2, a3):
    return os.open(cls.mem_read_cstr(a1), a2, a3)

def close(cls, a1):
    os.close(a1)

def lseek(cls, a1, a2, a3):
    return os.lseek(a1, a2, a3)

def mmap(cls, a1, a2, a3, a4, a5, a6):
    return cls.mmap(a2, addr_hint=a1)

def munmap(cls, a1, a2):
    pass

SYSCALLS = {
    'exit': (exit, 1),
    'fork': (fork, 0),
    'read': (read, 3),
    'write': (write, 3),
    'open': (open, 3), # variable length args?
    'close': (close, 1),
    'lseek': (lseek, 3),
    'mmap': (mmap, 6),
    'munmap': (munmap, 2),
}

def stack_args(cls):
    def _stack_args(n):
        cls.pop()
        return [cls.pop() for i in xrange(n)]
    return _stack_args

def call(cls, table, num, get_args):
    name = table.get(num)
    try:
        f, n = SYSCALLS[name]
    except KeyError:
        print 'Unsupported syscall:', num, name
        sys.exit(1)
    args = get_args(n)
    return f(cls, *args) or 0
