from capstone import *
from unicorn import *
from unicorn.arm_const import *

bits = 64
radare = 'arm'
capstone_init = (CS_ARCH_ARM, CS_MODE_64)
sp = ARM_REG_SP
unicorn_init = (UC_ARCH_ARM, UC_MODE_64)
regs = ()
