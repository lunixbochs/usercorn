import os
import sys

def exit(cls, n):
    sys.exit(n)

def fork(cls):
    return os.fork()

def read(cls, a1, a2, a3):
    tmp = os.read(a1, a3)
    cls.mem_write(a2, tmp + '\0')
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
