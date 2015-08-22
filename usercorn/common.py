from capstone import *
import textwrap

STACK_SIZE = 8 * 1024 * 1024
STACK_BASE = 0x7FFF0000
BASE = 1024 * 1024
UC_MEM_ALIGN = 8 * 1024

def capstone_disas(mem, addr, arch):
    md = Cs(*arch.capstone_init)
    return '\n'.join([
        '0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str)
        for i in md.disasm(str(mem), addr)
    ])

disas = capstone_disas

def align(addr, size, to=UC_MEM_ALIGN, grow=False):
    right = addr + size
    right = ((right + to - 1) & ~to) + 1
    addr &= ~(to - 1)
    size = right - addr
    if grow:
        size = (size + (to - 1)) & (~ (to - 1))
    return addr, size

def spaces(s, stride=4):
    return ' '.join(textwrap.wrap(s, stride))
