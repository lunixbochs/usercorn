from capstone import *
from unicorn import *
from unicorn.mips_const import *

bits = 32
radare = 'mips'
capstone_init = (CS_ARCH_MIPS, CS_MODE_32)
sp = MIPS_REG_SP
unicorn_init = (UC_ARCH_MIPS, UC_MODE_32)
regs = ()
