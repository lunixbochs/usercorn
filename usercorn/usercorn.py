from cStringIO import StringIO
from capstone import *
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from macholib.MachO import MachO
from macholib import mach_o
from unicorn import *
from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.m68k_const import *
from unicorn.mips_const import *
from unicorn.sparc_const import *
from unicorn.x86_const import *
import binascii
import os
import struct
import sys
import textwrap

def make_arch_info():
    keys = ['bits', 'csarch', 'csbits', 'ucarch', 'ucbits', 'sp', 'radare']
    d = lambda *values: dict(zip(keys, values))
    return {
        'x64': d(64, CS_ARCH_X86, CS_MODE_64, UC_ARCH_X86, UC_MODE_64, X86_REG_RSP, 'x86'),
        'x86': d(32, CS_ARCH_X86, CS_MODE_32, UC_ARCH_X86, UC_MODE_32, X86_REG_ESP, 'x86'),
        'ARM': d(32, CS_ARCH_ARM, CS_MODE_32, UC_ARCH_ARM, UC_MODE_32, ARM_REG_SP, 'arm'),
        'AArch64': d(64, CS_ARCH_ARM, CS_MODE_64, UC_ARCH_ARM, UC_MODE_64, ARM64_REG_SP, 'arm'),
        'MIPS': d(32, CS_ARCH_MIPS, CS_MODE_32, UC_ARCH_MIPS, UC_MODE_32, MIPS_REG_SP, 'mips'),
    }
ARCH_INFO = make_arch_info()
ARCH_MAP = {'x86_64': 'x64', 'i386': 'x86'}
REG_MAP = {
    'x64': (
        (X86_REG_RAX, "rax"),
        (X86_REG_RBX, "rbx"),
        (X86_REG_RCX, "rcx"),
        (X86_REG_RDX, "rdx"),
        (X86_REG_RSI, "rsi"),
        (X86_REG_RDI, "rdi"),
        (X86_REG_R8, "r8"),
        (X86_REG_R9, "r9"),
        (X86_REG_R10, "r10"),
        (X86_REG_R11, "r11"),
        (X86_REG_R12, "r12"),
        (X86_REG_R13, "r13"),
        (X86_REG_R14, "r14"),
        (X86_REG_R15, "r15"),
    )
}

STACK_SIZE = 8 * 1024 * 1024
STACK_BASE = 0x7FFF0000
BASE = 1024 * 1024
UC_MEM_ALIGN = 8 * 1024

def capstone_disas(mem, addr, info):
    md = Cs(info['csarch'], info['csbits'])
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

class FileMachO(MachO):
    def __init__(self, name, fileobj=None):
        MachO.__init__(self, name)
        if fileobj:
            MachO.load(self, fileobj)
        else:
            with open(name, 'rb') as fp:
                MachO.load(self, fp)

    def load(self, fileobj):
        pass

class UserCorn:
    def __init__(self, exe):
        # uses StringIO so we don't burn the file descriptor
        with open(exe, 'rb') as f:
            self.fp = StringIO(f.read())
        magic = self.fp.read(4).encode('hex')
        self.fp.seek(0)
        self.elf = None
        self.macho = None
        self.arch = None
        self.info = None
        self.symtab = None
        self.entry = None
        if magic == '7f454c46':
            self.elf = ELFFile(self.fp)
            self.arch = self.elf.get_machine_arch()
            self.entry = self.elf['e_entry']
            self.symtab = self.elf.get_section_by_name('.symtab')
            self.info = ARCH_INFO.get(self.arch)
        elif magic in ('cafebabe', 'feedface', 'feedfacf', 'cefaedfe', 'cffaedfe'):
            macho = FileMachO(exe, self.fp)
            for header in macho.headers:
                if header.endian == '<':
                    self.macho = header
                    self.arch = mach_o.CPU_TYPE_NAMES.get(header.header.cputype)
                    self.arch = ARCH_MAP.get(self.arch, self.arch)
                    self.info = ARCH_INFO.get(self.arch)
                    for lc, cmd, data in header.commands:
                        # entry point
                        if lc.cmd == mach_o.LC_MAIN or lc.cmd == mach_o.LC_UNIXTHREAD:
                            if self.info['bits'] == 64:
                                ip = 2 * 4 + 16 * 8
                                self.entry = struct.unpack(header.endian + 'Q', data[ip:ip+8])[0]
                            else:
                                ip = 2 * 4 + 10 * 4
                                self.entry = struct.unpack(header.endian + 'L', data[ip:ip+4])[0]
                    break
            else:
                raise NotImplementedError('Could not find suitable MachO arch.')
        else:
            raise NotImplementedError('Unrecognized file magic: %s' % magic)

        if not self.info:
            raise NotImplementedError('Unsupported Unicorn arch: %s' % self.arch)
        self.bits = self.info['bits']
        self.bsz = self.bits / 8
        self.sp = self.info['sp']
        self.regs = REG_MAP.get(self.arch, [])
        self.memory = []
        self.saved_regs = {}

    # start Unicorn helpers

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
        if mapped:
            a, b = mapped
            if addr < a:
                size = a - addr
            elif addr < b and addr + size > b:
                right = addr + size
                addr = b
                size = right - addr
            else:
                return
        addr, size = align(addr, size, grow=True)
        self.memory.append((addr, size))
        return self.mu.mem_map(addr, size)

    def mmap(self, size, addr_hint=0):
        if not addr_hint:
            addr_hint = BASE
        _, size = align(0, size, grow=True)
        addr_hint, size = align(addr_hint, size)
        for addr in xrange(addr_hint, 2 ** 32, UC_MEM_ALIGN):
            if not self.mapped(addr, size):
                # FIXME: why is this broken without size + 1
                self.mem_map(addr, size + 1)
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

    def mem_write(self, addr, data):
        return self.mu.mem_write(addr, data)

    def mem_read(self, addr, size):
        return self.mu.mem_read(addr, size)

    def mem_read_cstr(self, addr):
        # FIXME: this might be buggy
        s = ''
        while not '\0' in s:
            s += self.mu.mem_read(addr, 4)
            addr += 4
        return str(s.split('\0', 1)[0])

    def reg_write(self, reg, n):
        return self.mu.reg_write(reg, n)

    def reg_read(self, reg):
        return self.mu.reg_read(reg)

    def mem_hex(self, addr, size):
        data = binascii.hexlify(self.mem_read(addr, size))
        return spaces(data, self.bsz * 2)

    def read_regs(self):
        return [(enum, name, self.reg_read(enum)) for enum, name in self.regs]

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
        print disas(mem, addr, self.info)

    def pack_addr(self, n):
        if self.bits == 64:
            return struct.pack('<Q', n)
        else:
            return struct.pack('<I', n)

    def unpack_addr(self, data):
        if self.bits == 64:
            n, = struct.unpack('<Q', data)
        else:
            n, = struct.unpack('<I', data)
        return n

    # end Unicorn helpers

    def symbolicate(self, addr):
        if self.symtab:
            matches = defaultdict(list)
            for sym in self.symtab.iter_symbols():
                val = sym['st_value']
                size = sym['st_size']
                if sym['st_info']['type'] == 'STT_FUNC' and val <= addr and val + size > addr:
                    matches[addr - val].append(sym)
            if matches:
                # TODO pick the smallest matching symbol?
                # or indicate when you're inside multiple symbols?
                dist = sorted(matches.keys())[0]
                sym = matches[dist][0]
                return '%s+0x%02x' % (sym.name, dist)
        return '0x%x' % addr

    def map_segments(self):
        if self.elf:
            for s in self.elf.iter_segments():
                addr, size = s['p_paddr'], s['p_memsz']
                if not size:
                    continue
                self.mem_map(addr, size)
                self.mem_write(addr, s.data())
        elif self.macho:
            for lc, cmd, data in self.macho.commands:
                if lc.cmd in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
                    c = self.fp.tell()
                    for seg in data:
                        self.fp.seek(seg.offset)
                        sd = self.fp.read(seg.size)
                        self.mem_map(seg.addr, seg.size)
                        self.mem_write(seg.addr, sd)
                    self.fp.seek(c)
        self.stack = self.mmap(STACK_SIZE, STACK_BASE)
        self.reg_write(self.sp, self.stack + STACK_SIZE - self.bsz)

    def write_argv(self, argv):
        size = sum([len(a) + 1 for a in argv])
        argv_addr = self.mmap(size)
        pos = argv_addr + size
        addrs = []
        for arg in reversed(argv):
            asz = len(arg) + 1
            self.mem_write(pos - asz, arg)
            pos -= asz
            addrs.append(pos)
        for addr in [0] + addrs:
            self.push(addr)
        return argv_addr

    # hooks

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(">>> Memory fault on WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
            self.mem_map(address, 2 * 1024 * 1024)
            return True
        else:
            # stop emulation
            return False

    def hook_syscall(self, mu, user_data):
        if self.arch == 'x64':
            regs = [X86_REG_RAX, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_R10, X86_REG_R8, X86_REG_R9]
            num, a1, a2, a3, a4, a5, a6 = [self.reg_read(r) for r in regs]
            ret = 0
            if num == 0: # SYS_read
                tmp = os.read(a1, a3)
                self.mem_write(a2, tmp + '\0')
                ret = len(tmp)
            elif num == 1: # SYS_write
                ret = os.write(a1, self.mem_read(a2, a3))
            elif num == 2: # SYS_open
                ret = os.open(self.mem_read_cstr(a1), a2, a3)
            elif num == 3: # SYS_close
                os.close(a1)
            elif num == 8: # SYS_lseek
                ret = os.lseek(a1, a2, a3)
            elif num == 9: # SYS_mmap
                ret = self.mmap(a2, addr_hint=a1)
            elif num == 11: # SYS_munmap
                pass
            elif num == 60: # SYS_exit
                sys.exit(a1)
            else:
                print 'Unsupported syscall:', num
                sys.exit(1)
            self.reg_write(X86_REG_RAX, ret)
        else:
            print 'Arch not supported.'
            sys.exit(1)

    def hook_intr(self, mu, intno, user_data):
        if intno == 80:
            return self.hook_syscall(mu, user_data)

    def hook_block(self, uc, address, size, user_data):
        name = self.symbolicate(address)
        print(">>> Basic block at %s, block size = 0x%x <<<" % (name, size))
        self.print_changed_regs()

    def hook_code(self, uc, addr, size, user_data):
        if size > 128:
            print 'Makeshift SIGILL'
            sys.exit(1)
        print '>',
        self.print_dis(addr, size)

    def hook_mem_access(self, uc, access, addr, size, value, user_data):
        if access == UC_MEM_WRITE:
            print 'W @0x%x 0x%x = 0x%x' % (addr, size, value)
        else:
            print ('R @0x%x 0x%x =' % (addr, size)), self.mem_hex(addr, size)

    def run(self, *argv):
        self.mu = Uc(self.info['ucarch'], self.info['ucbits'])
        self.map_segments()
        # self.mu.hook_add(UC_HOOK_BLOCK, self.hook_block)
        # self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        self.mu.hook_add(UC_HOOK_INTR, self.hook_intr)
        self.mu.hook_add(UC_HOOK_INSN, self.hook_syscall, None, X86_INS_SYSCALL)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        # self.mu.hook_add(UC_HOOK_MEM_READ_WRITE, self.hook_mem_access)

        # put argv into target memory
        self.push(0) # envp
        argv_addr = self.write_argv(argv)
        self.push(len(argv)) # argc
        argv_size = sum([len(a) + 1 for a in argv]) + self.bsz * (len(argv) + 1)
        print '[argv]', self.mem_hex(argv_addr, argv_size)

        print '[entry point]'
        self.print_dis(self.entry, 64)
        print '[initial stack]', self.mem_hex(self.reg_read(self.sp), 64)

        print '====================================='
        print '==== Program output begins here. ===='
        print '====================================='
        self.mu.emu_start(self.entry, 0)
