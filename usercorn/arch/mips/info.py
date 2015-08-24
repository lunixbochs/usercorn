from capstone import *
from unicorn import *
from unicorn.mips_const import *

bits = 32
radare = 'mips'
capstone_init = (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
sp = MIPS_REG_SP
unicorn_init = (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
regs = ()
