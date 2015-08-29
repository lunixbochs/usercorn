from capstone import *
from unicorn import *
from unicorn.x86_const import *

bits = 32
radare = 'x86'
capstone_init = (CS_ARCH_X86, CS_MODE_32)
sp = UC_X86_REG_ESP
unicorn_init = (UC_ARCH_X86, UC_MODE_32)
regs = (
    (UC_X86_REG_EAX, "eax"),
    (UC_X86_REG_EBX, "ebx"),
    (UC_X86_REG_ECX, "ecx"),
    (UC_X86_REG_EDX, "edx"),
    (UC_X86_REG_ESI, "esi"),
    (UC_X86_REG_EDI, "edi"),
)
