import os
import sys

def exit(cls, n):
    sys.exit(n)

def write(cls, a1, a2, a3):
    os.write(a1, cls.mem_read(a2, a3))
