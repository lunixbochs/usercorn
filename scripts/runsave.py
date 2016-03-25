from savestate import load
from unicorn import *
from unicorn.x86_const import *
import sys

def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print ">>> Memory fault on WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value)
    else:
        print ">>> Memory fault on READ at 0x%x, data size = %u" % (address, size)
    return False

def hook_block(uc, addr, size, user_data):
    print ">>> Basic block at 0x%x, block size = 0x%x <<<" % (addr, size)

def hook_code(uc, addr, size, user_data):
    print 'code 0x%08x,+%d' % (addr, size)

def hook_mem_access(uc, access, addr, size, value, user_data):
    if access == UC_MEM_WRITE:
        print 'W @0x%x 0x%x = 0x%x' % (addr, size, value)
    else:
        memhex = uc.mem_read(addr, size).encode('hex')
        print 'R @0x%x 0x%x = %s' % (addr, size, memhex)

def hook_syscall(uc, user_data):
    print 'unhandled syscall'

def hook_intr(uc, intno, user_data):
    print 'unhandled interrupt', intno

def run(filename):
    uc, pc = load(filename)
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_BLOCK, hook_block)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    uc.hook_add(UC_HOOK_MEM_VALID, hook_mem_access)
    uc.hook_add(UC_HOOK_INSN, hook_syscall, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_INSN, hook_syscall, 1, 0, UC_X86_INS_SYSENTER)
    uc.hook_add(UC_HOOK_INTR, hook_intr)
    uc.emu_start(pc, -1)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage: %s <replay file>' % sys.argv[0]
        sys.exit(1)
    run(sys.argv[1])
