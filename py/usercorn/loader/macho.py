from collections import defaultdict, OrderedDict
from macholib import mach_o
from macholib.MachO import MachO
from macholib.mach_o import MH_MAGIC_64, MH_CIGAM_64
import struct

from .common import fp_head

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

def readSymTab(header, fp, bits):
    cmd = header.getSymbolTableCommand()
    fp.seek(cmd.stroff)
    strtab = fp.read(cmd.strsize)
    fp.seek(cmd.symoff)
    if bits == 64:
        nlist = mach_o.nlist_64
    else:
        nlist = mach_o.nlist
    syms = []
    for i in xrange(cmd.nsyms):
        n = nlist.from_fileobj(fp, _endian_=header.endian)
        syms.append((strtab[n.n_un:strtab.find('\0', n.n_un)], n))
    return OrderedDict(syms)

class MachOLoader:
    @staticmethod
    def test(fp):
        return fp_head(fp, 4) in ('cafebabe', 'feedface', 'feedfacf', 'cefaedfe', 'cffaedfe')

    def __init__(self, exe, fp):
        # NeXT?
        self.os = 'darwin'
        self.fp = fp
        self.macho = FileMachO(exe, fp)
        for header in self.macho.headers:
            if header.endian == '<':
                self.header = header
                self.arch = mach_o.CPU_TYPE_NAMES.get(header.header.cputype)
                if self.header.MH_MAGIC in (MH_MAGIC_64, MH_CIGAM_64):
                    self.bits = 64
                else:
                    self.bits = 32
                for lc, cmd, data in header.commands:
                    # entry point
                    if lc.cmd == mach_o.LC_MAIN or lc.cmd == mach_o.LC_UNIXTHREAD:
                        if self.bits == 64:
                            ip = 2 * 4 + 16 * 8
                            self.entry = struct.unpack(header.endian + 'Q', data[ip:ip+8])[0]
                        else:
                            ip = 2 * 4 + 10 * 4
                            self.entry = struct.unpack(header.endian + 'L', data[ip:ip+4])[0]
                break
        else:
            raise NotImplementedError('Could not find suitable MachO arch.')

        self.symtab = readSymTab(self.header, fp, self.bits)

    def segments(self):
        for lc, cmd, data in self.header.commands:
            if lc.cmd in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
                for seg in data:
                    self.fp.seek(seg.offset)
                    sd = self.fp.read(seg.size)
                    yield seg.addr, seg.size, sd

    def symbolicate(self, addr):
        matches = defaultdict(list)
        for name, cmd in self.symtab.items():
            val = cmd.n_value
            if val <= addr:
                matches[addr - val].append(name)
        return matches

__all__ = ['MachOLoader']
