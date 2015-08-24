from capstone import *
from unicorn import *
from unicorn.arm64_const import *

bits = 64
radare = 'arm'
capstone_init = (CS_ARCH_ARM64, CS_MODE_ARM)
sp = UC_ARM64_REG_SP
unicorn_init = (UC_ARCH_ARM64, UC_MODE_ARM)
regs = ()
