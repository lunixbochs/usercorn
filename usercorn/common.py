from capstone import *
import binascii
import textwrap

STACK_SIZE = 8 * 1024 * 1024
STACK_BASE = 0x7FFF0000
BASE = 1024 * 1024
UC_MEM_ALIGN = 8 * 1024

def capstone_disas(mem, addr, arch, padhex=0):
    md = Cs(*arch.capstone_init)
    disasm = list(md.disasm(str(mem), addr))
    hwidth = max(max(len(i.bytes) * 2 for i in disasm), padhex)
    mwidth = max(len(i.mnemonic) for i in disasm)
    return '\n'.join([
        '0x%x: %s %s %s' % (
            i.address,
            binascii.hexlify(i.bytes).rjust(hwidth),
            i.mnemonic.ljust(mwidth),
            i.op_str,
        )
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
