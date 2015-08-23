from collections import defaultdict
from elftools.elf.elffile import ELFFile

from .common import fp_head

class ELFLoader:
    MAGIC = '7f454c46'
    ELFFile = ELFFile

    @classmethod
    def test(cls, fp):
        return fp_head(fp) == cls.MAGIC

    def __init__(self, exe, fp):
        self.fp = fp
        self.elf = self.ELFFile(fp)
        self.symtab = self.elf.get_section_by_name('.symtab')
        self.arch = self.elf.get_machine_arch()
        self.entry = self.elf['e_entry']

    def segments(self):
        for s in self.elf.iter_segments():
            addr, size = s['p_paddr'], s['p_memsz']
            if not size:
                continue
            yield addr, size, s.data()

    def symbolicate(self, addr):
        matches = defaultdict(list)
        for sym in self.symtab.iter_symbols():
            val = sym['st_value']
            size = sym['st_size']
            if sym['st_info']['type'] == 'STT_FUNC' and val <= addr and val + size > addr:
                matches[addr - val].append(sym)
        return matches

__all__ = ['ELFLoader']
