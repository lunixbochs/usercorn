from cgc import CGCLoader
from elf import ELFLoader
from macho import MachOLoader

LOADERS = [
    ELFLoader,
    MachOLoader,
    CGCLoader,
]

def load(exe):
    from cStringIO import StringIO
    # uses StringIO so we don't burn a file descriptor in the guest
    with open(exe, 'rb') as f:
        fp = StringIO(f.read())

    for loader in LOADERS:
        if loader.test(fp):
            return loader(exe, fp)
    raise NotImplementedError('Could not find loader for executable.')
