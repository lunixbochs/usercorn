from unicorn import *
import binascii
import struct

from .common import align, disas, spaces, BASE, UC_MEM_ALIGN

class Unicorn(Uc):
    def __init__(self, arch):
        self.memory = []
        self.saved_regs = {}
        self.arch = arch
        self.bsz = self.arch.bits / 8
        self.sp = self.arch.sp
        Uc.__init__(self, *arch.unicorn_init)

    def mapped(self, addr, size):
        for a, b in self.memory:
            b += a
            if addr < a and addr + size > a:
                return (a, b)
            if addr >= a and addr < b:
                return (a, b)
        return False

    def mem_map(self, addr, size):
        # TODO: this tracking could be replaced by a Unicorn api to get memory map
        # FIXME: if you overlap with the end of an existing map it will silently fail
        mapped = self.mapped(addr, size)
        while mapped:
            a, b = mapped
            if addr < a:
                size = a - addr
            elif addr < b and addr + size > b:
                right = addr + size
                addr = b
                size = right - addr
            else:
                return
            mapped = self.mapped(addr, size)
        addr, size = align(addr, size, grow=True)
        self.memory.append((addr, size))
        return Uc.mem_map(self, addr, size)

    def mmap(self, size, addr_hint=0):
        if not addr_hint:
            addr_hint = BASE
        _, size = align(0, size, grow=True)
        addr_hint, size = align(addr_hint, size)
        for addr in xrange(addr_hint, 2 ** 32, UC_MEM_ALIGN):
            if not self.mapped(addr, size):
                self.mem_map(addr, size)
                return addr
        else:
            raise MemoryError('could not allocate %d bytes' % size)

    def push(self, n):
        sp = self.reg_read(self.sp)
        self.reg_write(self.sp, sp - self.bsz)
        self.mem_write(sp - self.bsz, self.pack_addr(n))

    def pop(self):
        data = self.mem_read(self.reg_read(self.sp), self.bsz)
        self.reg_write(self.sp, sp + self.bsz)
        return self.unpack_addr(data)

    def mem_read_cstr(self, addr):
        # FIXME: this might be buggy
        s = ''
        while not '\0' in s:
            s += self.mem_read(addr, 4)
            addr += 4
        return str(s.split('\0', 1)[0])

    def mem_hex(self, addr, size):
        data = binascii.hexlify(self.mem_read(addr, size))
        return spaces(data, self.bsz * 2)

    def read_regs(self):
        return [(enum, name, self.reg_read(enum)) for enum, name in self.arch.regs]

    def print_regs(self, regs=None):
        if regs is None:
            regs = self.read_regs()
        for i, (enum, name, val) in enumerate(regs):
            if i % 4 == 0 and i > 0:
                print
            print ('%3s=0x%08x' % (name, val)),
        print

    def print_changed_regs(self):
        regs = self.read_regs()
        changed = [(enum, name, val)
                   for enum, name, val in regs
                   if self.saved_regs.get(enum) != val]
        self.print_regs(changed)
        for enum, name, val in changed:
            self.saved_regs[enum] = val

    def print_dis(self, addr, size):
        mem = self.mem_read(addr, size)
        print disas(mem, addr, self.arch, padhex=self.bsz * 2)

    def pack_addr(self, n):
        if self.arch.bits == 64:
            return struct.pack('<Q', n)
        else:
            return struct.pack('<I', n)

    def unpack_addr(self, data):
        if self.arch.bits == 64:
            n, = struct.unpack('<Q', data)
        else:
            n, = struct.unpack('<I', data)
        return n
