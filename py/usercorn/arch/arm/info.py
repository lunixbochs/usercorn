from capstone import *
from unicorn import *
from unicorn.arm_const import *

bits = 32
radare = 'arm'
capstone_init = (CS_ARCH_ARM, CS_MODE_ARM)
sp = UC_ARM_REG_SP
unicorn_init = (UC_ARCH_ARM, UC_MODE_ARM)
regs = ()
