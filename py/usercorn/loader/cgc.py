from elftools.elf.elffile import ELFFile

from .elf import ELFLoader

class CGCFile(ELFFile):
    def _identify_file(self):
        self.elfclass = 32
        self.little_endian = True

class CGCLoader(ELFLoader):
    MAGIC = '7f434743'
    ELFFile = CGCFile

    def __init__(self, *args, **kwargs):
        ELFLoader.__init__(self, *args, **kwargs)
        self.arch = 'x86'
        self.os = 'cgc'
