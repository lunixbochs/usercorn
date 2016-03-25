import zlib
import struct
import sys
import unicorn
from unicorn.x86_const import UC_X86_REG_RIP

HEADER = struct.Struct('>IIIIIQQ')

def read(filename):
    with open(filename, 'r') as f:
        data = f.read()

    if data[:4] != 'UCSV':
        raise Exception('Bad magic:' + repr(data[:4]))
    ver, ucmaj, ucmin, ucarch, ucmode, pc, datalen = HEADER.unpack(data[4:4 + HEADER.size])
    if ver != 1:
        raise Exception('Bad savefile version: %d != 1' % ver)

    '''
    if ucmaj != unicorn.UC_API_MAJOR or ucmin != unicorn.UC_API_MINOR:
        raise Exception('Mismatched Unicorn version: %d.%d != %s' % (ucmaj, ucmin, unicorn.__version__))
    '''

    rest = data[4 + HEADER.size:]
    if datalen < len(rest):
        raise Exception('Unexpected end of file.')
    rest = zlib.decompress(rest[:datalen])

    uc = unicorn.Uc(ucarch, ucmode)

    regs = []
    reg_count, = struct.unpack('>Q', rest[:8])
    rest = rest[8:]
    for i in xrange(reg_count):
        enum, val = struct.unpack('>QQ', rest[:16])
        regs.append((enum, val))
        rest = rest[16:]

    regions = []
    region_count, = struct.unpack('>Q', rest[:8])
    rest = rest[8:]
    for i in xrange(region_count):
        addr, size, prot = struct.unpack('>QQI', rest[:20])
        if size == 0:
            # if there was an error packing on the source, a region might be blank
            continue
        rest = rest[20:]
        regions.append((addr, size, prot, rest[:size]))
        rest = rest[size:]

    return ucarch, ucmode, pc, regs, regions

def load(filename):
    arch, mode, pc, regs, regions = read(filename)
    uc = unicorn.Uc(arch, mode)
    for enum, val in regs:
        uc.reg_write(enum, val)
    for addr, size, prot, data in regions:
        uc.mem_map(addr, size, prot)
        uc.mem_write(addr, data)
    return uc, pc

def dump(filename):
    arch, mode, pc, regs, regions = read(filename)
    addrfmt = '0x%%0%dx' % (16 if mode & unicorn.UC_MODE_64 else 8)
    find = (lambda scope, prefix, inside=None:
        dict((v, k) for k, v in vars(scope).items()
             if k.startswith(prefix) and (inside is None or inside in k)))

    lookup = find(unicorn, 'UC_MODE_')
    lookup[unicorn.UC_MODE_64] = 'UC_MODE_64' # fix MIPS64
    modes = []
    for i in xrange(mode.bit_length()):
        bit = 1 << i
        if mode & bit:
            modes.append(lookup[bit])

    archstr = find(unicorn, 'UC_ARCH_')[arch]
    print 'uc_open(%s, %s)' % (archstr, '|'.join(modes))
    # oh mercy what am I doing
    const = getattr(unicorn, '%s_const' % archstr.lower().split('_')[-1])

    print
    maxlen = 0
    lookup = find(const, 'UC_', 'REG')
    for enum, _ in regs:
        maxlen = max(len(lookup[enum]), maxlen)
    for enum, val in regs:
        if not val:
            continue
        name = (lookup[enum] + ',').ljust(maxlen + 1)
        print ('uc_reg_write(%s ' + addrfmt + ')') % (name, val)

    prot_bits = find(unicorn, 'UC_PROT_')

    print
    for addr, size, prot, data in regions:
        prot = '|'.join([prot_bits[i] for i in xrange(prot.bit_length()) if prot & i])
        print ('uc_mem_map(' + addrfmt + ', 0x%08x, %s)') % (addr, size, prot)

    print
    print 'uc_emu_start(0x%x, -1)' % pc

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage: %s <unicorn state file>' % sys.argv[0]
        sys.exit(1)

    dump(sys.argv[1])
