from elf import ELFLoader
from macho import MachOLoader

def load(exe):
    from cStringIO import StringIO
    # uses StringIO so we don't burn a file descriptor in the guest
    with open(exe, 'rb') as f:
        fp = StringIO(f.read())

    if ELFLoader.test(fp):
        return ELFLoader(exe, fp)
    elif MachOLoader.test(fp):
        return MachOLoader(exe, fp)
    else:
        raise NotImplementedError('Could not find loader for executable.')
