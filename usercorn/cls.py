from unicorn import *
from unicorn.x86_const import UC_X86_INS_SYSCALL
from unicorn.arm_const import *
import binascii
import os
import struct
import sys

from common import align
from common import BASE, STACK_SIZE, STACK_BASE
from corn import Unicorn
import arch
import loader

class UserCorn:
    def __init__(self, exe):
        self.loader = loader.load(exe)
        self.entry = self.loader.entry
        self.arch_name = arch.map(self.loader.arch)
        self.os_name = self.loader.os
        self.arch, self.os = arch.find(self.arch_name, self.os_name)
        if not self.arch:
            raise NotImplementedError('Unsupported arch: %s' % self.arch_name)
        if not self.os:
            raise NotImplementedError('Unsupported OS: %s' % self.os_name)
        self.bsz = self.arch.bits / 8
        self.uc = Unicorn(self.arch)

    def symbolicate(self, addr):
        matches = self.loader.symbolicate(addr)
        if matches:
            # TODO pick the smallest matching symbol?
            # or indicate when you're inside multiple symbols?
            dist = sorted(matches.keys())[0]
            name = matches[dist][0]
            return '%s+0x%02x' % (name, dist)
        return '0x%x' % addr

    def map_segments(self):
        for addr, size, data in self.loader.segments():
            self.uc.mem_map(addr, size)
            # FIXME: weird, if I don't touch the data before write it segfaults on ARM
            # Issue #15
            binascii.hexlify(data)
            self.uc.mem_write(addr, data)
        # TODO: ask loader for stack size/location
        self.stack = self.uc.mmap(STACK_SIZE, addr_hint=STACK_BASE)
        self.uc.reg_write(self.arch.sp, self.stack + STACK_SIZE - self.bsz)

    def write_argv(self, argv):
        size = sum([len(a) + 1 for a in argv])
        argv_addr = self.uc.mmap(size)
        pos = argv_addr + size
        addrs = []
        for arg in reversed(argv):
            asz = len(arg) + 1
            self.uc.mem_write(pos - asz, arg)
            pos -= asz
            addrs.append(pos)
        for addr in [0] + addrs:
            self.uc.push(addr)
        return argv_addr

    # hooks

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(">>> Memory fault on WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
            self.uc.mem_map(address, 2 * 1024 * 1024)
            return True
        else:
            # stop emulation
            return False

    def hook_block(self, uc, addr, size, user_data):
        name = self.symbolicate(addr)
        print (">>> Basic block at %s, block size = 0x%x <<<" % (name, size))
        self.uc.print_changed_regs()
        self.uc.print_dis(addr, size)

    def hook_code(self, uc, addr, size, user_data):
        if size > 128:
            print 'Makeshift SIGILL'
            sys.exit(1)
        self.uc.print_dis(addr, size)

    def hook_mem_access(self, uc, access, addr, size, value, user_data):
        if access == UC_MEM_WRITE:
            print 'W @0x%x 0x%x = 0x%x' % (addr, size, value)
        else:
            print ('R @0x%x 0x%x =' % (addr, size)), self.uc.mem_hex(addr, size)

    def hook_syscall(self, mu, user_data):
        self.os.syscall(self.uc)

    def hook_intr(self, mu, intno, user_data):
        self.os.interrupt(self.uc, intno)

    def run(self, *argv):
        self.map_segments()
        if self.uc.reg_read(self.arch.sp) == 0:
            print 'Warning: sp == 0.'

        # self.uc.hook_add(UC_HOOK_BLOCK, self.hook_block)
        # self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(UC_HOOK_INTR, self.hook_intr)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        self.uc.hook_add(UC_HOOK_INSN, self.hook_syscall, None, UC_X86_INS_SYSCALL)
        # self.uc.hook_add(UC_HOOK_MEM_READ_WRITE, self.hook_mem_access)

        # put argv into target memory
        self.uc.push(0) # envp
        argv_addr = self.write_argv(argv)
        self.uc.push(len(argv)) # argc
        argv_size = sum([len(a) + 1 for a in argv]) + self.bsz * (len(argv) + 1)
        print '[argv]', self.uc.mem_hex(argv_addr, argv_size)

        print '[entry point]'
        self.uc.print_dis(self.entry, 64)
        print '[initial stack]', self.uc.mem_hex(self.uc.reg_read(self.arch.sp), 64)

        print '====================================='
        print '==== Program output begins here. ===='
        print '====================================='
        self.uc.emu_start(self.entry, 0)
