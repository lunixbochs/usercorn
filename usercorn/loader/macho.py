from macholib.MachO import MachO
from macholib import mach_o
import struct

from .. import arch
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

class MachOLoader:
    @staticmethod
    def test(fp):
        return fp_head(fp, 4) in ('cafebabe', 'feedface', 'feedfacf', 'cefaedfe', 'cffaedfe')

    def __init__(self, exe, fp):
        self.fp = fp
        self.macho = FileMachO(exe, fp)
        for header in self.macho.headers:
            if header.endian == '<':
                self.header = header
                self.arch = mach_o.CPU_TYPE_NAMES.get(header.header.cputype)
                bits = arch.find(self.arch).bits
                for lc, cmd, data in header.commands:
                    # entry point
                    if lc.cmd == mach_o.LC_MAIN or lc.cmd == mach_o.LC_UNIXTHREAD:
                        if bits == 64:
                            ip = 2 * 4 + 16 * 8
                            self.entry = struct.unpack(header.endian + 'Q', data[ip:ip+8])[0]
                        else:
                            ip = 2 * 4 + 10 * 4
                            self.entry = struct.unpack(header.endian + 'L', data[ip:ip+4])[0]
                break
        else:
            raise NotImplementedError('Could not find suitable MachO arch.')

    def segments(self):
        for lc, cmd, data in self.header.commands:
            if lc.cmd in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
                for seg in data:
                    self.fp.seek(seg.offset)
                    sd = self.fp.read(seg.size)
                    yield seg.addr, seg.size, sd

    def symbolicate(self, addr):
        pass

__all__ = ['MachOLoader']
